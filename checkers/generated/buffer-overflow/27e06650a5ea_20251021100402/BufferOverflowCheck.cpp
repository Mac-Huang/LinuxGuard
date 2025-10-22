//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "BufferOverflowCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {

void BufferOverflowCheck::registerMatchers(MatchFinder *Finder) {
  Finder->addMatcher(
      callExpr(callee(functionDecl(hasName("snprintf"))),
               hasAncestor(functionDecl(hasName("target_lu_gp_members_show"))),
               unless(anyOf(
                   hasAncestor(ifStmt(hasCondition(binaryOperator(
                                                   hasOperatorName(">="),
                                                   hasLHS(declRefExpr(to(varDecl(hasName("cur_len"))))),
                                                   hasRHS(integerLiteral(equals(256))))))),
                   hasAncestor(callExpr(callee(functionDecl(hasName("memcpy")))))
               )))
               .bind("snprintf_call"),
      this);
}

void BufferOverflowCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *MatchedCallExpr = Result.Nodes.getNodeAs<CallExpr>("snprintf_call");
  if (MatchedCallExpr) {
    diag(MatchedCallExpr->getBeginLoc(), "Potential buffer overflow in target_lu_gp_members_show due to missing check of snprintf return value or inadequate size check.");
  }
}

} // namespace clang::tidy::linuxkernel