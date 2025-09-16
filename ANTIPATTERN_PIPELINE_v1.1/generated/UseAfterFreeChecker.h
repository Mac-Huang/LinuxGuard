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

  void reportBug(ExplodedNode *N, const MemRegion *R, const std::string &Msg,
                 BugReporter &BR);

  static void registerChecker(CheckerRegistry &Registry);
};

} // namespace ento
} // namespace clang

#endif // USEAFTERFREECHECKER_H
