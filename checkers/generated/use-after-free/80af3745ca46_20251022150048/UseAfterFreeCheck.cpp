//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UseAfterFreeCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/ASTContext.h"

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {

void UseAfterFreeCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      ifStmt(hasCondition(
                 expr(hasUnaryOperand(
                          callExpr(callee(functionDecl(hasName("of_changeset_add_property")))))
                           .bind("ret_check"))),
             hasThen(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasName("__of_prop_free"))))
                                                      .bind("free_call"))))
                 .bind("if_stmt"),
             hasElse(stmt())),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *If = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (!If)
    return;
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  if (!FreeCall)
    return;

  // Find the variable being freed.  Assume it's the first argument.
  const Expr *Arg = FreeCall->getArg(0);
  if (!Arg)
    return;

  // Find where the variable is used after the free.

  SourceLocation FreeLoc = FreeCall->getEndLoc();
  if (!FreeLoc.isValid())
      return;

  const Stmt *Then = If->getThen();
  if (!Then)
    return;
  const CompoundStmt *CS = dyn_cast<CompoundStmt>(Then);
  if (!CS)
      return;

  for (const auto *S : CS->body()) {
    StatementMatcher UseMatcher = anyOf(
        memberExpr(member(hasName("next")), hasBase(expr(hasDescendant(equalsNode(Arg))))).bind("use"),
        memberExpr(member(hasName("deadprops")), hasBase(expr(hasDescendant(equalsNode(Arg))))).bind("use")
    );

    MatchFinder Finder;
    Finder.addMatcher(UseMatcher, this);
    Finder.match(*S, *Result.Context);
  }
}

} // namespace clang::tidy::linuxkernel