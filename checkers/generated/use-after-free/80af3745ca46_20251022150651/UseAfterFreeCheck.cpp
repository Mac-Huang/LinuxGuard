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
                      ),
                      unaryOperator(
                          hasOperatorName("!"),
                          hasUnaryOperand(callExpr(callee(functionDecl(hasName("of_changeset_add_property")))))
                      )
                  )
              )
              ,
          hasThen(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasName("__of_prop_free")))).bind("free_call"))))
      ).bind("if_stmt"), this);

  Finder->addMatcher(
      memberExpr(
          member(hasName("next")),
          hasBase(
              declRefExpr(
                  to(varDecl(hasName("new_pp")))
              )
          )
      ).bind("use_after_free"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
    if (const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt")) {
        const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
        if (!FreeCall)
          return;

        const auto *UseAfterFree = Result.Nodes.getNodeAs<MemberExpr>("use_after_free");

        if (UseAfterFree) {
            SourceLocation FreeLoc = FreeCall->getBeginLoc();
            SourceLocation UseLoc = UseAfterFree->getExprLoc();
            if (UseLoc.isValid() && FreeLoc.isValid() &&
                Result.Context->getSourceManager().isBeforeInTranslationUnit(FreeLoc, UseLoc))
            {
               diag(UseAfterFree->getExprLoc(), "use-after-free: 'new_pp' is used after being freed.");
            }
        }
    }
}

} // namespace clang::tidy::linuxkernel