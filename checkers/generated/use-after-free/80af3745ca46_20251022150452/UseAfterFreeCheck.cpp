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
      ifStmt(
          hasCondition(
              expr(
                  anyOf(
                      binaryOperator(
                          hasOperatorName("!=") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )) ,
                          hasRHS(integerLiteral(equals(0)))
                      ),
                      binaryOperator(
                          hasOperatorName("<") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )) ,
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
                          hasArgument(0,
                                      declRefExpr(to(varDecl(hasType(pointerType()))))
                                      .bind("freed_ptr")
                          )
                      )
                  )
              )
          ),
          unless(hasThen(compoundStmt(hasDescendant(returnStmt()))))
      ).bind("if_stmt"), Finder);

  Finder->addMatcher(
      memberExpr(
          member(hasName("next")),
          hasObjectExpression(
              declRefExpr(to(varDecl(hasType(pointerType()))).bind("used_ptr"))
          ),
          hasParent(
              binaryOperator(hasOperatorName("="),
                             hasLHS(ignoringParenCasts(memberExpr(hasObjectExpression(declRefExpr(to(varDecl(hasType(pointerType()))).bind("check_ptr")))))),
                             hasRHS(anything())
              )
          ),
          isWithinBodyOf(functionDecl())
      ).bind("use_after_free"), Finder);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (!IfStmt)
    return;

  const auto *FreedPtr = Result.Nodes.getNodeAs<DeclRefExpr>("freed_ptr");
  if (!FreedPtr)
    return;

  const auto *UsedPtr = Result.Nodes.getNodeAs<DeclRefExpr>("used_ptr");
  if (!UsedPtr)
    return;

  const auto *Use = Result.Nodes.getNodeAs<MemberExpr>("use_after_free");
  if (!Use)
    return;

  if (const auto *FreedDecl = dyn_cast<VarDecl>(FreedPtr->getDecl())) {
    if (const auto *UsedDecl = dyn_cast<VarDecl>(UsedPtr->getDecl())) {
        if (FreedDecl == UsedDecl) {
            diag(Use->getBeginLoc(), "potential use-after-free detected")
                << FreedDecl->getNameAsString();
        }
    }
  }
}

} // namespace clang::tidy::linuxkernel