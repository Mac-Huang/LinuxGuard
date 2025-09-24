c++
#ifndef BUFFER_OVERFLOW_CHECKER_H
#define BUFFER_OVERFLOW_CHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/SmallVector.h"

namespace clang {
namespace checker {

class BufferOverflowChecker : public Checker<check::PreStmt<DeclStmt>,
                                            check::PreStmt<BinaryOperator>,
                                            check::PreStmt<ArraySubscriptExpr>,
                                            check::PreStmt<CallExpr>> {
public:
  bool EvalDeclStmt(const DeclStmt *DS, CheckerContext &C) const;
  bool EvalBinaryOperator(const BinaryOperator *BO, CheckerContext &C) const;
  bool EvalArraySubscriptExpr(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  bool EvalCallExpr(const CallExpr *CE, CheckerContext &C) const;

  void checkPreStmt(const DeclStmt *DS, CheckerContext &C) const;
  void checkPreStmt(const BinaryOperator *BO, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const;

  static void registerCheckers(clang::checker::CheckerManager &mgr);
};

} // namespace checker
} // namespace clang

#endif // BUFFER_OVERFLOW_CHECKER_H