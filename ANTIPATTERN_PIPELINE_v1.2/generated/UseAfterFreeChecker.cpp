#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::ento;

namespace {

class UseAfterFreeChecker : public Checker<check::ASTDecl<FunctionDecl>,
                                          check::PostStmt<IfStmt>,
                                          check::PostStmt<CallExpr>,
                                          check::PreStmt<CallExpr>> {
  BugType *BT;

  // State for tracking allocations
  struct AllocationInfo {
    SourceLocation AllocationLoc;
    std::string AllocatorName;
    std::string AllocatorType;
    Stmt *AllocationStmt;
  };

  // State for tracking potential vulnerabilities
  struct UseAfterFreeState {
    AllocationInfo AllocInfo;
    SourceLocation FreeLoc;
    Stmt *FreeStmt;
    Stmt *IfStmt;
    Stmt *CallStmt;
  };

  using State = ProgramStateRef;

public:
  UseAfterFreeChecker() : BT(nullptr) {}

  void checkASTDecl(const FunctionDecl *FD, AnalysisManager &AM,
                    BugReporter &BR) const {
    BT = new BugType(this, "Use-After-Free", "Memory Error");
    BT->setSuppressInAnalyzerConfig(true);
  }

  // Check for memory allocation
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return;

    const std::string FunctionName = FD->getNameInfo().getName().getAsString();

    if (FunctionName == "kmalloc" || FunctionName == "kzalloc" ||
        FunctionName == "malloc" || FunctionName == "calloc") {
      const Expr *ArgExpr = CE->getArg(0);
      if (!ArgExpr)
        return;

      const Stmt *ParentStmt = CE->getParentStmt();
      if (!ParentStmt)
        return;

      const DeclStmt *DS = dyn_cast<DeclStmt>(ParentStmt);
      if (!DS)
        return;

      const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if (!VD)
        return;

      AllocationInfo AllocInfo;
      AllocInfo.AllocationLoc = CE->getBeginLoc();
      AllocInfo.AllocatorName = FunctionName;
      AllocInfo.AllocatorType = VD->getType().getAsString();
      AllocInfo.AllocationStmt = const_cast<Stmt *>(CE);

      State state = C.getState();
      state = state->set<PointerIntMap<AllocationInfo>>(VD, AllocInfo);
      C.addTransition(state);
    }
  }

  // Check for function calls that might fail and error handling
  void checkPostStmt(const CallExpr *CE, CheckerContext &C) const {
    const FunctionDecl *FD = CE->getDirectCallee();
    if (!FD)
      return;

    const std::string FunctionName = FD->getNameInfo().getName().getAsString();

    if (FunctionName == "of_changeset_add_property") {
      const Stmt *ParentStmt = CE->getParentStmt();
      if (!ParentStmt)
        return;

      const DeclStmt *DS = dyn_cast<DeclStmt>(ParentStmt);
      if (!DS)
        return;

      const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      if (!VD)
        return;

      State state = C.getState();
      AllocationInfo AllocInfo;
      if (state->get<PointerIntMap<AllocationInfo>>(VD, AllocInfo)) {
        // Check if the return value is used in an if statement
        const IfStmt *IS = dyn_cast<IfStmt>(ParentStmt->getParentStmt());
        if (!IS)
          return;

        const BinaryOperator *BO =
            dyn_cast<BinaryOperator>(IS->getCond());
        if (!BO)
          return;

        if (BO->getOpcode() != BO_NotEqual)
          return;

        const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(BO->getRHS());
        if (!IL)
          return;

        if (IL->getValue() != 0)
          return;

        UseAfterFreeState UAFState;
        UAFState.AllocInfo = AllocInfo;
        UAFState.IfStmt = const_cast<Stmt *>(IS);
        UAFState.CallStmt = const_cast<Stmt *>(CE);
        state = state->set<PointerIntMap<UseAfterFreeState>>(VD, UAFState);
        C.addTransition(state);
      }
    }
  }

  // Check for conditional free
  void checkPostStmt(const IfStmt *IS, CheckerContext &C) const {
    State state = C.getState();
    for (auto &entry : state->get<PointerIntMap<UseAfterFreeState>>()) {
      const VarDecl *VD = entry.first;
      UseAfterFreeState UAFState = entry.second;

      if (UAFState.IfStmt != IS)
        continue;

      const Stmt *Then = IS->getThen();
      if (!Then)
        continue;

      const CompoundStmt *CS = dyn_cast<CompoundStmt>(Then);
      if (!CS)
        continue;

      for (const Stmt *S : CS->body()) {
        const CallExpr *CE = dyn_cast<CallExpr>(S);
        if (!CE)
          continue;

        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD)
          continue;

        const std::string FunctionName = FD->getNameInfo().getName().getAsString();
        if (FunctionName != "__of_prop_free" && FunctionName != "kfree" &&
            FunctionName != "free")
          continue;

        const Expr *ArgExpr = CE->getArg(0);
        if (!ArgExpr)
          continue;

        const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ArgExpr);
        if (!DRE)
          continue;

        if (DRE->getDecl() != VD)
          continue;

        UAFState.FreeLoc = CE->getBeginLoc();
        UAFState.FreeStmt = const_cast<Stmt *>(CE);
        state = state->set<PointerIntMap<UseAfterFreeState>>(VD, UAFState);
        C.addTransition(state);
      }
    }
  }

  // Check for use after free
  void checkPostStmt(const Stmt *S, CheckerContext &C) const {
    State state = C.getState();
    for (auto &entry : state->get<PointerIntMap<UseAfterFreeState>>()) {
      const VarDecl *VD = entry.first;
      UseAfterFreeState UAFState = entry.second;

      if (!UAFState.FreeStmt.isValid())
        continue;

      if (S == UAFState.IfStmt)
        continue;

      if (S == UAFState.CallStmt)
        continue;

      if (isa<CompoundStmt>(S))
        continue;

      if (isa<DeclStmt>(S))
        continue;

      if (isa<ReturnStmt>(S))
        continue;

      if (isa<NullStmt>(S))
        continue;

      if (isa<IfStmt>(S))
        continue;

      if (isa<BinaryOperator>(S))
        continue;

      if (isa<UnaryOperator>(S))
        continue;

      if (isa<ImplicitCastExpr>(S))
        continue;

      if (isa<ParenExpr>(S))
        continue;

      if (isa<CastExpr>(S))
        continue;

      if (isa<ConditionalOperator>(S))
        continue;

      if (isa<CXXOperatorCallExpr>(S))
        continue;

      if (isa<CXXMemberCallExpr>(S))
        continue;

      if (isa<CXXConstructExpr>(S))
        continue;

      if (isa<CXXNewExpr>(S))
        continue;

      if (isa<CXXDeleteExpr>(S))
        continue;

      if (isa<ArraySubscriptExpr>(S))
        continue;

      if (isa<MemberExpr>(S)) {
        const MemberExpr *ME = dyn_cast<MemberExpr>(S);
        if (!ME)
          continue;

        const Expr *Base = ME->getBase();
        if (!Base)
          continue;

        const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Base);
        if (!DRE)
          continue;

        if (DRE->getDecl() != VD)
          continue;

        reportBug(UAFState, C);
        return;
      }

      if (isa<UnaryOperator>(S)) {
        const UnaryOperator *UO = dyn_cast<UnaryOperator>(S);
        if (!UO)
          continue;

        if (UO->getOpcode() == UO_AddrOf)
          continue;

        const Expr *SubExpr = UO->getSubExpr();
        if (!SubExpr)
          continue;

        const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(SubExpr);
        if (!DRE)
          continue;

        if (DRE->getDecl() != VD)
          continue;

        reportBug(UAFState, C);
        return;
      }
    }
  }

  void reportBug(const UseAfterFreeState &UAFState, CheckerContext &C) const {
    PathDiagnosticBuilder B(C.getBugReporter(), BT);
    B.addRange(UAFState.AllocInfo.AllocationStmt->getSourceRange());
    B.addVisitor(
        [UAFState](PathDiagnosticPiece &P, BugReport &BR) {
          SmallString<256> buf;
          llvm::raw_svector_ostream os(buf);
          os << "Memory allocated at ";
          P.setMainPieceText(os.str());
        },
        UAFState.AllocInfo.AllocationStmt->getSourceRange());

    B.addRange(UAFState.CallStmt->getSourceRange());
    B.addVisitor(
        [UAFState](PathDiagnosticPiece &P, BugReport &BR) {
          SmallString<256> buf;
          llvm::raw_svector_ostream os(buf);
          os << "Function call that might fail";
          P.setMainPieceText(os.str());
        },
        UAFState.CallStmt->getSourceRange());

    B.addRange(UAFState.FreeStmt->getSourceRange());
    B.addVisitor(
        [UAFState](PathDiagnosticPiece &P, BugReport &BR) {
          SmallString<256> buf;
          llvm::raw_svector_ostream os(buf);
          os << "Memory freed at ";
          P.setMainPieceText(os.str());
        },
        UAFState.FreeStmt->getSourceRange());

    B.addRange(UAFState.IfStmt->getSourceRange());
    B.addVisitor(
        [UAFState](PathDiagnosticPiece &P, BugReport &BR) {
          SmallString<256> buf;
          llvm::raw_svector_ostream os(buf);
          os << "Conditional free based on the return value of the function call";
          P.setMainPieceText(os.str());
        },
        UAFState.IfStmt->getSourceRange());

    B.addRange(UAFState.IfStmt->getSourceRange());
    B.addVisitor(
        [UAFState](PathDiagnosticPiece &P, BugReport &BR) {
          SmallString<256> buf;
          llvm::raw_svector_ostream os(buf);
          os << "Use after free";
          P.setMainPieceText(os.str());
        },
        UAFState.IfStmt->getSourceRange());

    auto R = std::make_unique<BugReport>(*BT, BT->getDescription(),
                                         B.getReportLocation(UAFState.FreeStmt),
                                         B.buildPath());
    C.emitReport(std::move(R));
  }
};
} // namespace

void ento::registerUseAfterFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<UseAfterFreeChecker>();
}

bool ento::shouldRegisterUseAfterFreeChecker(const CheckerManager &mgr) {
  return true;
}