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
                      ),
                      binaryOperator(
                          hasOperatorName("<") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )),
                          hasRHS(integerLiteral(equals(0)))
                      ),
                      binaryOperator(
                          hasOperatorName(">") ,
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
                  hasAnySubstatement(
                      callExpr(
                          callee(functionDecl(hasName("__of_prop_free"))),
                          hasArgument(0, hasDescendant(declRefExpr(to(varDecl(hasName("new_pp"))))))
                      ).bind("free_call")
                  )
              )
          ),
          unless(hasThen(compoundStmt(hasAnySubstatement(returnStmt())))) // Prevent false positives by allowing returns on the 'then' branch.
      )
      .bind("if_stmt"),

      this);
      
    Finder->addMatcher(
        memberExpr(
          member(hasName("next")),
          hasObject(declRefExpr(to(varDecl(hasName("new_pp")))))
        ).bind("use_after_free"),
        this
    );
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
    const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
    if (!IfStmt)
        return;

    const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
    if (!FreeCall)
        return;

    const auto *UseAfterFree = Result.Nodes.getNodeAs<MemberExpr>("use_after_free");
    if (UseAfterFree) {
        diag(UseAfterFree->getExprLoc(), "Potential use-after-free: 'new_pp' is freed in the error path, then dereferenced.");
    }
}

} // namespace clang::tidy::linuxkernel