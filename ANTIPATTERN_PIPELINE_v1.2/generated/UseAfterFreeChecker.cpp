#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathSensitiveBugReport.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {

class UseAfterFreeChecker : public Checker<check::PostCall, check::PreStmt<MemberExpr>,
                                          check::PreStmt<UnaryOperator>,
                                          check::PreStmt<ArraySubscriptExpr>> {
public:
  static void *getTag() {
    static int tag = 0;
    return &tag;
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreStmt(const MemberExpr *E, CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *E, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *E, CheckerContext &C) const;

private:
  bool isFreeLikeFunction(const CallEvent &Call) const;
  void reportUAF(const MemRegion *R, const ExplodedNode *N, CheckerContext &C) const;
};

bool UseAfterFreeChecker::isFreeLikeFunction(const CallEvent &Call) const {
  const auto *calleeDecl = Call.getDecl();
  if (!calleeDecl) return false;
  const auto *calleeName = calleeDecl->getNameAsString();
  return calleeName == "free" || calleeName == "kfree" || calleeName == "__of_prop_free";
}

void UseAfterFreeChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (!isFreeLikeFunction(Call)) return;
  const LocationContext *LC = C.getLocationContext();
  const MemRegion *freedRegion = Call.getArgSVal(0).getAsRegion();
  if (!freedRegion) return;

  C.addTransition(C.getState()->add<FreedMemory>(freedRegion, LC));
}

void UseAfterFreeChecker::checkPreStmt(const MemberExpr *E, CheckerContext &C) const {
  const MemRegion *R = C.getState()->getSVal(E->getBase()).getAsRegion();
  if (R) {
    if (C.getState()->contains<FreedMemory>(R)) {
      reportUAF(R, C.getPredecessor(), C);
    }
  }
}

void UseAfterFreeChecker::checkPreStmt(const UnaryOperator *E, CheckerContext &C) const {
  if (E->getOpcode() != UO_Deref) return;
  const MemRegion *R = C.getState()->getSVal(E->getSubExpr()->IgnoreParenCasts()).getAsRegion();
  if (R) {
    if (C.getState()->contains<FreedMemory>(R)) {
      reportUAF(R, C.getPredecessor(), C);
    }
  }
}

void UseAfterFreeChecker::checkPreStmt(const ArraySubscriptExpr *E, CheckerContext &C) const {
  const MemRegion *R = C.getState()->getSVal(E->getBase()).getAsRegion();
  if (R) {
    if (C.getState()->contains<FreedMemory>(R)) {
      reportUAF(R, C.getPredecessor(), C);
    }
  }
}

void UseAfterFreeChecker::reportUAF(const MemRegion *R, const ExplodedNode *N, CheckerContext &C) const {
  auto *BT = C.getBugReporter().getBugType(this, "Use-after-free", "Use-after-free");
  auto R1 = R;
  std::string msg = "Use-after-free";
  auto report = std::make_unique<PathSensitiveBugReport>(*BT, msg, N);
  report->addRange(R1->getExtent());
  C.emitReport(std::move(report));
}

} // namespace

namespace clang {
namespace ento {

template <>
struct ProgramStateTrait<FreedMemory>
    : public ProgramStatePartialTrait<FreedMemory> {
  static void* GDM;
  static bool isTracked(ProgramStateRef state, const MemRegion* R) {
    return state->get<FreedMemory>(R);
  }
  static void setToTrue(ProgramStateRef state, const MemRegion* R) {
    state = state->add<FreedMemory>(R, state->getLocationContext());
  }
  static void setToFalse(ProgramStateRef state, const MemRegion* R) {
    state = state->remove<FreedMemory>(R);
  }
};

void* ProgramStateTrait<FreedMemory>::GDM = nullptr;

} // namespace ento
} // namespace clang

REGISTER_SET_WITH_PROGRAMSTATE(FreedMemory, const MemRegion*)

void ento::registerUseAfterFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<UseAfterFreeChecker>();
}