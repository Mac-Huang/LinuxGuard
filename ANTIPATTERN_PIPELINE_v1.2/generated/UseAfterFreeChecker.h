c++
#ifndef USEAFTERFREECHECKER_H
#define USEAFTERFREECHECKER_H

#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/SmallVector.h"

namespace clang {
namespace ento {

class UseAfterFreeChecker : public Checker<check::DeadSymbols,
                                          check::PreStmt<CXXDeleteExpr>,
                                          check::PostStmt<CXXDeleteExpr>,
                                          check::PreStmt<CXXNewExpr>,
                                          check::PostStmt<CXXNewExpr>,
                                          check::PreStmt<MemberExpr>,
                                          check::PreStmt<ArraySubscriptExpr>,
                                          check::PreStmt<UnaryOperator>,
                                          check::PreStmt<DeclRefExpr>> {
public:
  UseAfterFreeChecker();

  bool evalDeadSymbols(const ProgramStateRef &state, SymbolReaper &SR,
                       const LocationContext *LCtx) const;

  void checkPreStmt(const CXXDeleteExpr *E, CheckerContext &C) const;
  void checkPostStmt(const CXXDeleteExpr *E, CheckerContext &C) const;
  void checkPreStmt(const CXXNewExpr *E, CheckerContext &C) const;
  void checkPostStmt(const CXXNewExpr *E, CheckerContext &C) const;
  void checkPreStmt(const MemberExpr *E, CheckerContext &C) const;
  void checkPreStmt(const ArraySubscriptExpr *E, CheckerContext &C) const;
  void checkPreStmt(const UnaryOperator *E, CheckerContext &C) const;
  void checkPreStmt(const DeclRefExpr *E, CheckerContext &C) const;

private:
  using AllocationMap = llvm::DenseMap<const MemRegion *, ProgramStateRef>;
  using AllocationInfo = std::pair<const Stmt *, const LocationContext *>;
  using AllocationHistory = llvm::SmallVector<AllocationInfo, 4>;

  ProgramStateRef markAllocated(ProgramStateRef state, const MemRegion *MR,
                                const Stmt *S, const LocationContext *LCtx) const;
  ProgramStateRef markFreed(ProgramStateRef state, const MemRegion *MR,
                            const Stmt *S, const LocationContext *LCtx) const;
  bool isFreed(ProgramStateRef state, const MemRegion *MR) const;
  void reportUseAfterFree(const MemRegion *MR, const Stmt *S,
                          const LocationContext *LCtx, CheckerContext &C) const;
};

} // namespace ento
} // namespace clang

void registerUseAfterFreeChecker(CheckerManager &mgr);

#endif