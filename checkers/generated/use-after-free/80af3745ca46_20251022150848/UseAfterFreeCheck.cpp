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
      ifStmt(hasCondition(
                 expr(hasUnaryOperand(
                          callExpr(callee(functionDecl(hasName("of_changeset_add_property")))))
                        .bind("call_result"),
                       hasOperatorName("!"))),
             hasThen(compoundStmt(has(callExpr(callee(functionDecl(
                                     hasName("__of_prop_free"))),
                                         hasArgument(0, expr().bind("freed_ptr")))))
                         .bind("free_block"))
          )
          .bind("if_stmt"),
      this);

  Finder->addMatcher(
      memberExpr(member(hasName("next")),
                 hasBase(anyOf(
                     // Match a direct use of the freed pointer
                     declRefExpr(to(expr(hasType(pointsTo(qualType(hasCanonicalType(pointsTo(anything()))))))).bind("freed_ptr")),
                     // Match a use of a pointer derived from the freed pointer
                     memberExpr(hasBase(declRefExpr(to(expr().bind("freed_ptr")))))
                     )))
          .bind("member_expr"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (!IfStmt)
    return;

  const auto *CallResult = Result.Nodes.getNodeAs<Expr>("call_result");
  const auto *FreePtr = Result.Nodes.getNodeAs<Expr>("freed_ptr");

  if (!CallResult || !FreePtr)
    return;

  const auto *FreeBlock = Result.Nodes.getNodeAs<CompoundStmt>("free_block");
  if (!FreeBlock)
    return;

  if (const auto *MemberExpr = Result.Nodes.getNodeAs<MemberExpr>("member_expr")) {
      SourceLocation UseLocation = MemberExpr->getBeginLoc();
      const Expr *Base = MemberExpr->getBase();
      if (!Base)
        return;
      diag(UseLocation, "Potential use-after-free: '%0' is freed in the if statement and potentially used after")
          << FreePtr;
  }
}

} // namespace clang::tidy::linuxkernel