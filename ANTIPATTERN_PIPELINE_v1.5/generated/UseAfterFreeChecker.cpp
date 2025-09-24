#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/Optional.h"

using namespace clang;
using namespace ento;

namespace {

class UseAfterFreeChecker : public Checker<checkPostCall> {
public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
};

void UseAfterFreeChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  const auto *FE = dyn_cast<FunctionDecl>(Call.getDecl());
  if (!FE)
    return;

  StringRef Name = FE->getName();
  if (Name != "free" && Name != "delete" && Name != "of_prop_free") // Add other free functions as needed
    return;

  const Expr *Arg = Call.getArg(0);
  if (!Arg)
    return;

  SVal Pointer = C.getState()->getSVal(Arg);
  if (!Pointer.isNonNull())
    return;

  // Track the freed pointer.  This is a simplified approach; a more robust
  // implementation might use a more sophisticated data structure to handle
  // multiple frees of the same pointer.
  C.addTransition(C.getState()->BindExpr(Arg, UnknownVal()));


  // Check for subsequent dereferences.  This is a simplified approach; a more
  // robust implementation would use a more sophisticated data flow analysis.
  for (auto I = C.getAnalysisManager().getCFG()->begin(); I != C.getAnalysisManager().getCFG()->end(); ++I) {
    const CFGBlock *Block = *I;
    for (const CFGElement &Element : *Block) {
      if (const auto *Stmt = Element.getAs<Stmt>()) {
        if (const auto *BinaryOperator = dyn_cast<BinaryOperator>(Stmt)) {
          if (BinaryOperator->getOpcode() == BO_PtrMemD) {
            const Expr *Base = BinaryOperator->getLHS()->IgnoreParenCasts();
            if (C.getState()->getSVal(Base) == Pointer) {
              ExplodedNode *N = C.generateErrorNode();
              if (N) {
                PathSensitiveBugReport *report = new PathSensitiveBugReport(
                    *this, "Use-after-free", categories::MemoryError, N,
                    "Use of pointer after it has been freed");
                C.emitReport(report);
              }
              return;
            }
          }
        } else if (const auto *UnaryOperator = dyn_cast<UnaryOperator>(Stmt)) {
          if (UnaryOperator->getOpcode() == UO_Deref) {
            const Expr *Operand = UnaryOperator->getSubExpr()->IgnoreParenCasts();
            if (C.getState()->getSVal(Operand) == Pointer) {
              ExplodedNode *N = C.generateErrorNode();
              if (N) {
                PathSensitiveBugReport *report = new PathSensitiveBugReport(
                    *this, "Use-after-free", categories::MemoryError, N,
                    "Use of pointer after it has been freed");
                C.emitReport(report);
              }
              return;
            }
          }
        }
      }
    }
  }
}

} // end anonymous namespace

void ento::registerUseAfterFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<UseAfterFreeChecker>();
}