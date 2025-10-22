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
              expr(hasUnaryOperator(
                  UO_LNot,
                  has(
                      callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          .bind("of_changeset_add_property_call"))))),
          hasThen(compoundStmt(has(callExpr(callee(functionDecl(hasName("__of_prop_free"))))
                                      .bind("free_call")))),
          hasElse(stmt().bind("else_stmt")))
          .bind("if_stmt"),
      this);

    Finder->addMatcher(
        ifStmt(
            hasCondition(
                expr(hasUnaryOperator(
                    UO_LNot,
                    has(
                        callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                            .bind("of_changeset_add_property_call"))))),
            hasThen(compoundStmt(has(callExpr(callee(functionDecl(hasName("__of_prop_free"))))
                                        .bind("free_call")))),
            unless(hasThen(compoundStmt(has(returnStmt())))),
            hasDescendant(memberExpr(member(hasName("next")),
                                     hasParent(declRefExpr(to(varDecl(hasType(pointsTo(anything()))).bind("freed_ptr"))))).bind("use_after_free_member"))
        ).bind("if_stmt_no_return"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (IfStmt) {
        const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
        if (FreeCall) {
            diag(FreeCall->getExprLoc(), "Potential use-after-free detected. 'new_pp' freed on error path but not returned.");
        }
  }

  const auto *IfStmtNoReturn = Result.Nodes.getNodeAs<IfStmt>("if_stmt_no_return");
  if (IfStmtNoReturn) {
    const auto *UseAfterFreeMember = Result.Nodes.getNodeAs<MemberExpr>("use_after_free_member");
    if(UseAfterFreeMember) {
            diag(UseAfterFreeMember->getExprLoc(), "Use-after-free detected. 'new_pp' used after being freed.");
    }

  }
}

} // namespace clang::tidy::linuxkernel