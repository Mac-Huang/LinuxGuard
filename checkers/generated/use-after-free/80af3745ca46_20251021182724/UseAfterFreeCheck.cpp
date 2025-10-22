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
                 expr(hasUnaryOperand(
                     callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                     .bind("call_of_changeset_add_property")))),
             hasThen(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasName("__of_prop_free"))).bind("free_call_new_pp")))))
             , hasElse(stmt()))
          .bind("if_stmt_with_free"), this);
  Finder->addMatcher(
      binaryOperator(hasOperatorName("="), hasLHS(memberExpr(member(hasName("next")), hasType(pointerType()))),
                      hasRHS(memberExpr(member(hasName("deadprops")), hasType(pointerType())))
                     ).bind("use_after_free"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt_with_free");
  const auto *CallExprOfChangeset = Result.Nodes.getNodeAs<CallExpr>("call_of_changeset_add_property");
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call_new_pp");
  const auto *Assignment = Result.Nodes.getNodeAs<BinaryOperator>("use_after_free");


  if (IfStmt && CallExprOfChangeset && FreeCall && Assignment) {
      SourceLocation FreeLoc = FreeCall->getBeginLoc();
      SourceLocation UseLoc = Assignment->getBeginLoc();
      diag(UseLoc, "potential use-after-free detected") << FreeLoc;
  }
}

} // namespace clang::tidy::linuxkernel