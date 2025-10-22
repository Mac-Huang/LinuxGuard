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
                          hasOperatorName("!=")
                      ),
                      binaryOperator(
                          hasOperatorName("==")
                      )
                  ),
                  hasLHS(
                      callExpr(
                          callee(
                              functionDecl(hasName("of_changeset_add_property"))
                          )
                      ).bind("of_changeset_add_property_call")
                  ),
                  hasRHS(
                      integerLiteral(equals(0))
                  )
              )
          ),
          hasThen(
              compoundStmt(
                  hasDescendant(
                      callExpr(
                          callee(
                              functionDecl(hasName("__of_prop_free"))
                          ),
                          hasArgument(0, hasDescendant(declRefExpr(to(varDecl(hasType(pointerType()))).bind("freed_pointer"))))
                      ).bind("free_call")
                  )
              ).bind("then_block")
          ),
          unless(hasThen(compoundStmt(hasDescendant(returnStmt()))))
      ).bind("if_statement"),
      this);

  Finder->addMatcher(
      memberExpr(
          member(hasName("next")),
          hasObjectExpression(
              declRefExpr(
                  to(varDecl(hasType(pointerType()), hasName("new_pp")))
              )
          ),
          hasParent(
              binaryOperator(
                  hasOperatorName("=")
              )
          )
      ).bind("use_after_free"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_statement");
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  const auto *UseAfterFree = Result.Nodes.getNodeAs<MemberExpr>("use_after_free");

  if (IfStmt && FreeCall && UseAfterFree) {
    diag(UseAfterFree->getExprLoc(), "Potential use-after-free detected. 'new_pp' is used after being freed.");
  }
}

} // namespace clang::tidy::linuxkernel