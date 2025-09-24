#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "llvm/ADT/SmallString.h"

using namespace clang;
using namespace ento;

namespace {

class BufferOverflowChecker : public Checker<check::ASTDecl<FunctionDecl>,
                                           check::PreStmt<ArraySubscriptExpr>,
                                           check::PreStmt<MemberExpr>,
                                           check::PreStmt<BinaryOperator>,
                                           check::PostCall> {
  BugType *BT_BO;

  // State for tracking data flow
  struct BufferInfo {
    const Expr *Base;
    SVal Size;
  };

  using BufferMap = llvm::DenseMap<const Expr *, BufferInfo>;
  using OffsetMap = llvm::DenseMap<const Expr *, SVal>;
  using DataOriginMap = llvm::DenseMap<const Expr *, const Stmt *>;

  // State for the checker
  struct BufferOverflowState {
    BufferMap Buffers;
    OffsetMap Offsets;
    DataOriginMap DataOrigins;

    BufferOverflowState() {}
    BufferOverflowState(const BufferOverflowState &X,
                        CheckerContext &C) : Buffers(X.Buffers),
                                             Offsets(X.Offsets),
                                             DataOrigins(X.DataOrigins) {}

    void *operator new(size_t Size, Allocator &A) {
      return A.Allocate(Size);
    }
  };

  // Helper functions
  bool isNetworkPacketHandlingFunction(const FunctionDecl *FD) const {
    if (!FD)
      return false;

    const IdentifierInfo *II = FD->getIdentifier();
    if (!II)
      return false;

    StringRef Name = II->getName();
    return Name.contains("sctp") || Name.contains("udp") || Name.contains("tcp");
  }

  bool isOffsetCalculation(const BinaryOperator *BO) const {
    if (!BO)
      return false;

    BinaryOperator::Opcode Op = BO->getOpcode();
    return Op == BO_Add || Op == BO_Sub;
  }

  bool isMemoryAccess(const Expr *E) const {
    if (!E)
      return false;

    if (isa<ArraySubscriptExpr>(E) || isa<MemberExpr>(E))
      return true;

    return false;
  }

public:
  BufferOverflowChecker() : BT_BO(nullptr) {}

  void checkASTDecl(const FunctionDecl *FD, AnalysisManager &AM,
                    BugReporter &BR) const {
    if (!BT_BO)
      BT_BO = new BugType(this, "Buffer Overflow", "SCTP");

    if (!isNetworkPacketHandlingFunction(FD))
      return;

    // Initialize the state for this function
    ProgramStateRef state = AM.getInitialWrappedState();
    BufferOverflowState *BOState = new (AM.getAllocator()) BufferOverflowState();
    state = state->set<BufferOverflowState>(BOState);
    AM.setInitialState(state);
  }

  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    auto *BOState = state->get<BufferOverflowState>();

    if (!BOState)
      return;

    const Expr *Base = ASE->getBase()->IgnoreParenCasts();
    const Expr *Idx = ASE->getIdx()->IgnoreParenCasts();

    auto BufferIt = BOState->Buffers.find(Base);
    if (BufferIt == BOState->Buffers.end())
      return;

    SVal OffsetVal = BOState->Offsets.lookup(Idx);
    if (OffsetVal.isUnknown())
      return;

    SVal BufferSize = BufferIt->second.Size;
    if (BufferSize.isUnknown())
      return;

    SValBuilder &SVB = C.getSValBuilder();
    SVal Zero = SVB.makeZeroVal(Idx->getType());
    SVal MaxOffset = SVB.evalBinOp(state, BO_Sub, BufferSize,
                                   SVB.makeIntVal(1, Idx->getType()),
                                   Idx->getType());

    if (MaxOffset.isUnknown())
      return;

    ConstraintManager &CM = C.getConstraintManager();
    ProgramStateRef state_safe, state_unsafe;
    std::tie(state_safe, state_unsafe) = CM.assume(state,
                                                   SVB.evalBinOp(state, BO_LE,
                                                                 OffsetVal,
                                                                 MaxOffset,
                                                                 Idx->getType()));

    if (state_unsafe) {
      SmallString<256> buf;
      llvm::raw_svector_ostream os(buf);
      os << "Potential buffer overflow: Accessing memory at offset ";
      OffsetVal.dump(os);
      os << " which is outside the bounds of buffer ";
      Base->printPretty(os, nullptr, C.getASTContext());
      os << ".";

      auto report = std::make_unique<PathSensitiveBugReport>(
          BT_BO, os.str(), state_unsafe);
      report->addRange(ASE->getSourceRange());
      BR.emitReport(std::move(report));
    }

    C.addTransition(state_safe);
  }

  void checkPreStmt(const MemberExpr *ME, CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    auto *BOState = state->get<BufferOverflowState>();

    if (!BOState)
      return;

    const Expr *Base = ME->getBase()->IgnoreParenCasts();

    auto BufferIt = BOState->Buffers.find(Base);
    if (BufferIt == BOState->Buffers.end())
      return;

    // TODO: Implement checks for member access based on offsets
  }

  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    auto *BOState = state->get<BufferOverflowState>();

    if (!BOState || !isOffsetCalculation(BO))
      return;

    const Expr *LHS = BO->getLHS()->IgnoreParenCasts();
    const Expr *RHS = BO->getRHS()->IgnoreParenCasts();

    // Track data origins for potential vulnerabilities
    if (BOState->DataOrigins.find(LHS) == BOState->DataOrigins.end() &&
        BOState->DataOrigins.find(RHS) == BOState->DataOrigins.end()) {
      BOState->DataOrigins.insert({BO, BO});
    }

    // Track offset calculations
    if (BO->getOpcode() == BO_Add) {
      SValBuilder &SVB = C.getSValBuilder();
      SVal LHSVal = state->getSVal(LHS);
      SVal RHSVal = state->getSVal(RHS);
      SVal Result = SVB.evalBinOp(state, BO_Add, LHSVal, RHSVal,
                                  BO->getType());
      BOState->Offsets.insert({BO, Result});
    }
    C.addTransition(state->set<BufferOverflowState>(BOState));
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef state = C.getState();
    auto *BOState = state->get<BufferOverflowState>();

    if (!BOState)
      return;

    const FunctionDecl *FD = Call.getDecl();
    if (!FD)
      return;

    StringRef FuncName = FD->getNameInfo().getName().getAsString();

    // Identify and track buffer information
    if (FuncName == "sctp_process_asconf") {
      const Expr *SkbArg = Call.getArg(0);
      if (SkbArg) {
        BOState->Buffers.insert({SkbArg, {SkbArg, C.getSValBuilder().makeIntVal(1024, C.getASTContext().IntTy)}}); // TODO: Get actual buffer size
      }
    }

    // Track data origins for potential vulnerabilities
    if (FuncName == "ntohs" || FuncName == "ntohl") {
      const Expr *Arg = Call.getArg(0);
      if (Arg) {
        BOState->DataOrigins.insert({Arg, Call.getOriginStmt()});
      }
    }

    C.addTransition(state->set<BufferOverflowState>(BOState));
  }
};

} // namespace

void ento::registerBufferOverflowChecker(CheckerManager &mgr) {
  mgr.registerChecker<BufferOverflowChecker>();
}