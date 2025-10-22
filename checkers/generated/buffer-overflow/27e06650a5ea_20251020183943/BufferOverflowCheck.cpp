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
      functionDecl(hasName("target_lu_gp_members_show"),
                   hasBody(compoundStmt(
                       hasDescendant(callExpr(callee(functionDecl(hasName("snprintf"))),
                                              hasParent(compoundStmt(
                                                  hasDescendant(binaryOperator(
                                                      isComparisonOperator(),
                                                      hasLHS(has(declRefExpr(hasDeclaration(varDecl(hasName("cur_len")))))),
                                                      hasRHS(integerLiteral(equals(256))))))))))))
          .bind("func"), this);
}

void BufferOverflowCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *MatchedFunc = Result.Nodes.getNodeAs<FunctionDecl>("func");
  if (MatchedFunc) {
      diag(MatchedFunc->getBeginLoc(), "potential buffer overflow in target_lu_gp_members_show");
  }
}

} // namespace clang::tidy::linuxkernel