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
                          callExpr(callee(functionDecl(hasName("of_changeset_add_property")))))
                            .bind("ret_val_call"),
                        unaryOperator(hasOperator(UO_LNot))))),
             hasThen(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasName("__of_prop_free"))),
                                                     hasArgument(0, expr(hasDeclRef(to(varDecl(hasName("new_pp"))))))
                                                             .bind("free_call")))),
             hasElse(stmt())),
      this);

  Finder->addMatcher(
      binaryOperator(
          hasOperator(BO_Assign),
          hasLHS(memberExpr(member(hasName("next")), hasDeclRef(to(varDecl(hasName("new_pp"))))))).bind("use_after_free"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  const auto *UseAfterFree = Result.Nodes.getNodeAs<BinaryOperator>("use_after_free");

  if (FreeCall && UseAfterFree) {
    diag(UseAfterFree->getExprLoc(), "Potential use-after-free: 'new_pp' is freed but then dereferenced")
        << UseAfterFree->getLHS()->getSourceRange();
  }
}

} // namespace clang::tidy::linuxkernel