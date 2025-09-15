#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "llvm/ADT/Optional.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {

class UseAfterFreeChecker : public Checker<check::PostCall, check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
};

// ProgramState tracking freed pointers
REGISTER_SET_WITH_PROGRAMSTATE(FreedPointers, SymbolRegionValue)

void UseAfterFreeChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  const auto *CE = dyn_cast<CallExpr>(Call.getOriginExpr());
  if (!CE) return;

  const auto *CalleeDecl = Call.getDecl();
  if (!CalleeDecl) return;

  StringRef CalleeName = CalleeDecl->getName();
  if (CalleeName != "free" && CalleeName != "delete" && CalleeName != "of_prop_free") return;

  const Expr *Arg = Call.getArg(0);
  if (!Arg) return;

  ProgramStateRef state = C.getState();
  SVal V = state->getSVal(Arg);
  if (!V.isNonNull()) return;

  const MemRegion *R = V.getAsRegion();
  if (!R) return;

  state = state->add<FreedPointers>(R);
  C.addTransition(state);
}

void UseAfterFreeChecker::checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const {
  if (BO->getOpcode() != BO_Assign) return;

  const Expr *LHS = BO->getLHS();
  const Expr *RHS = BO->getRHS();

  if (!LHS || !RHS) return;

  ProgramStateRef state = C.getState();
  SVal LHSVal = state->getSVal(LHS);
  if (!LHSVal.getAsRegion()) return;

  const MemRegion *LHSRegion = LHSVal.getAsRegion();
  if (!LHSRegion) return;

  if (state->contains<FreedPointers>(LHSRegion)) {
    ExplodedNode *N = C.generateErrorNode();
    if (!N) return;

    PathSensitiveBugReport *report = new PathSensitiveBugReport(*BT, "Use-after-free", N);
    report->addRange(BO->getSourceRange());
    C.emitReport(report);
  }
}

} // end anonymous namespace

void ento::registerUseAfterFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<UseAfterFreeChecker>();
}