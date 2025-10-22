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
      ifStmt(
          hasCondition(
              expr(
                  anyOf(
                      binaryOperator(
                          hasOperatorName("!=") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )),
                          hasRHS(integerLiteral(equals(0)))
                      )
                  )
              )
          ),
          hasThen(
              compoundStmt(
                  hasDescendant(
                      callExpr(
                          callee(functionDecl(hasName("__of_prop_free"))),
                          hasArgument(0, expr(hasType(pointerType().bind("freed_ptr"))).bind("freed_ptr_arg"))
                      ).bind("free_call")
                  )
              )
          ),
          unless(hasThen(compoundStmt(hasDescendant(returnStmt()))))
      )
      .bind("if_stmt"), this);

    Finder->addMatcher(
        memberExpr(
            member(hasName("next")),
            hasBase(expr(hasType(pointerType().bind("accessed_ptr"))).bind("accessed_ptr_arg"))
        ).bind("access_after_free"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
    if (const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt")) {
        const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
        const auto *FreedPtrArg = Result.Nodes.getNodeAs<Expr>("freed_ptr_arg");
        const auto *AccessedPtrArg = Result.Nodes.getNodeAs<Expr>("accessed_ptr_arg");

        if(FreeCall && FreedPtrArg && AccessedPtrArg) {
            if(FreedPtrArg == AccessedPtrArg) {
               diag(IfStmt->getLocStart(), "potential use-after-free: 'new_pp' is freed in the error path and potentially accessed afterwards.") << FreeCall->getExprLoc() ;
            }
        }
    }
}

} // namespace clang::tidy::linuxkernel