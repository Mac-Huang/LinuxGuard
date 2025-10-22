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
              anyOf(
                  binaryOperator(
                      hasOperatorName("!="),
                      hasLHS(ignoringParenCasts(
                          callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                      )),
                      hasRHS(integerLiteral(equals(0)))
                  ),
                  binaryOperator(
                      hasOperatorName("<"),
                      hasLHS(ignoringParenCasts(
                          callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                      )),
                      hasRHS(integerLiteral(equals(0)))
                  ),
                  binaryOperator(
                      hasOperatorName(">"),
                      hasLHS(ignoringParenCasts(
                          callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                      )),
                      hasRHS(integerLiteral(equals(0)))
                  )
              )
          ),
          hasThen(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasName("__of_prop_free")))).bind("free_call")))),
          unless(hasThen(compoundStmt(hasDescendant(returnStmt()))))
      ).bind("if_stmt"), this);

  Finder->addMatcher(
      memberExpr(
          member(hasName("next")),
          hasBase(
              declRefExpr(to(varDecl(hasType(pointerType()), hasName("new_pp"))))
          )
      ).bind("use_after_free"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  const auto *UseAfterFree = Result.Nodes.getNodeAs<MemberExpr>("use_after_free");

  if (IfStmt && FreeCall && UseAfterFree) {
    SourceLocation FreeLoc = FreeCall->getBeginLoc();
    SourceLocation UseLoc = UseAfterFree->getBeginLoc();

    if (UseLoc.isMacroID() || FreeLoc.isMacroID()) {
      return;
    }

    SourceRange FreeRange = FreeCall->getSourceRange();

    diag(UseLoc, "potential use-after-free detected: 'new_pp' is used after being freed") << FreeRange;
  }
}

} // namespace clang::tidy::linuxkernel