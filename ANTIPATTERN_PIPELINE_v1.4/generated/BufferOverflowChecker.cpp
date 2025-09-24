// AI-Generated Buffer Overflow Checker
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

using namespace clang;
using namespace ento;

namespace {
class BufferOverflowChecker : public Checker<check::PreCall> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};
}

void BufferOverflowChecker::checkPreCall(const CallEvent &Call,
                                         CheckerContext &C) const {
  // Check for unsafe functions
  if (!Call.isGlobalCFunction())
    return;

  StringRef FuncName = Call.getCalleeIdentifier()->getName();

  // Check for strcpy, strcat, sprintf, gets
  if (FuncName == "strcpy" || FuncName == "strcat" ||
      FuncName == "sprintf" || FuncName == "gets") {

    if (!BT)
      BT.reset(new BugType(this, "Buffer Overflow", "Security"));

    ExplodedNode *N = C.generateErrorNode();
    if (N) {
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Potential buffer overflow - unsafe function usage", N);
      C.emitReport(std::move(Report));
    }
  }
}

// Register the checker
void ento::registerBufferOverflowChecker(CheckerManager &mgr) {
  mgr.registerChecker<BufferOverflowChecker>();
}

bool ento::shouldRegisterBufferOverflowChecker(const CheckerManager &mgr) {
  return true;
}
