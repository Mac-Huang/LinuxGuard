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
                 expr(hasUnaryOperator(
                     UO_LNot, has(implicitCastExpr(has(callExpr(callee(
                                       functionDecl(hasName("of_changeset_add_property")))))))))),
             hasThen(compoundStmt(has(callExpr(
                         callee(functionDecl(hasName("__of_prop_free"))),
                         hasArgument(
                             0, hasDescendant(declRefExpr(to(varDecl(hasName("new_pp"))))))))),
                     hasFollowing(
                         stmt(hasDescendant(memberExpr(member(hasName("next")),
                                                       has(declRefExpr(
                                                           to(varDecl(hasName("new_pp")))))))))))
          .bind("use_after_free"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  if (const auto *MatchedIfStmt = Result.Nodes.getNodeAs<IfStmt>("use_after_free")) {
    diag(MatchedIfStmt->getThen()->getBeginLoc(),
         "Potential use-after-free detected: 'new_pp' is freed and then used.")
        << MatchedIfStmt->getSourceRange();
  }
}

} // namespace clang::tidy::linuxkernel