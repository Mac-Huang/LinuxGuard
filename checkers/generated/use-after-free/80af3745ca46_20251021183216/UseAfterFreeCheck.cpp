//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UseAfterFreeCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {

void UseAfterFreeCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      ifStmt(hasCondition(
                 expr(hasUnaryOperator(UO_LNot, has(callExpr(callee(functionDecl(hasName("of_changeset_add_property")))))))),
             hasThen(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasName("__of_prop_free"))),
                                                     hasArgument(0, hasDescendant(declRefExpr(to(varDecl(hasName("new_pp"))))))))),
                     unless(hasDescendant(returnStmt()))),
             hasBody(stmt(hasSuccessor(memberExpr(member(hasName("next")),
                                                   hasBase(declRefExpr(to(varDecl(hasName("new_pp"))))))))
                        .bind("use_after_free"))).bind("if_stmt"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *MatchedIfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (MatchedIfStmt) {
    const auto *MatchedUse = Result.Nodes.getNodeAs<Stmt>("use_after_free");
    if (MatchedUse) {
      diag(MatchedUse->getBeginLoc(), "use-after-free detected: 'new_pp' is used after being freed");
    }
  }
}

} // namespace clang::tidy::linuxkernel