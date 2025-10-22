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
                          hasOperatorName("!=") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )),
                          hasRHS(cxxNullPtrLiteralExpr())
                      )
                  )
              )
          ),
          hasThen(
              compoundStmt(
                  hasDescendant(
                      callExpr(callee(functionDecl(hasName("__of_prop_free")))).bind("free_call")
                  )
              ).bind("then_block")
          ),
          unless(hasThen(compoundStmt(hasDescendant(returnStmt())))) // Prevent false positives when return is present
      ).bind("if_stmt"),
      this);

  Finder->addMatcher(
      memberExpr(
          member(hasName("next")),
          hasObjectExpression(
              ignoringParenCasts(
                  declRefExpr(
                      to(varDecl(hasType(pointerType())))
                  ).bind("used_ptr")
              )
          ),
          hasParent(
              binaryOperator(hasOperatorName("="),
                             hasLHS(memberExpr(member(hasName("next")))))
          )
      ).bind("use_after_free"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (!IfStmt)
    return;

  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  if (!FreeCall)
    return;

  const auto *UsedPtr = Result.Nodes.getNodeAs<DeclRefExpr>("used_ptr");
  if (!UsedPtr)
    return;

  if (FreeCall->getNumArgs() == 0)
      return;

  const Expr* Arg = FreeCall->getArg(0);

  if (!Arg->isLValue())
    return;

  if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Arg->IgnoreParenCasts())) {
    if (DRE->getDecl() == UsedPtr->getDecl()) {
      diag(UsedPtr->getExprLoc(), "use-after-free detected: 'new_pp' is used after being freed.");
    }
  }
}

} // namespace clang::tidy::linuxkernel