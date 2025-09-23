#ifndef USEAFTERFREECHECKER_H
#define USEAFTERFREECHECKER_H

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

namespace clang {
namespace ento {

class UseAfterFreeChecker : public Checker<check::DeadStores> {
public:
  void checkPostStmt(const Stmt *S, AnalysisManager& mgr,
                     BugReporter &BR) override;

  void checkDeadStores(constento::MemRegion *R,
                      const Stmt *S, AnalysisManager& mgr,
                      BugReporter &BR) override;

  static void registerChecker(CheckerManager &mgr);
};

} // namespace ento
} // namespace clang

#endif // USEAFTERFREECHECKER_H