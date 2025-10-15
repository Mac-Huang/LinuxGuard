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
  auto OfChangesetAddProperty = callExpr(callee(functionDecl(hasName("of_changeset_add_property")))).bind("of_changeset_add_property_call");
  auto FreeCall = callExpr(callee(functionDecl(hasAnyName("__of_prop_free"))), hasArgument(0, declRefExpr(to(varDecl().bind("freed_ptr"))))).bind("free_call");


  Finder->addMatcher(
      ifStmt(hasCondition(binaryOperator(hasOperatorName("!="), hasLHS(ignoringParenImpCasts(OfChangesetAddProperty)), hasRHS(integerLiteral(equals(0))))),
             hasThen(compoundStmt(hasDescendant(FreeCall))),
             hasElse(stmt(unless(compoundStmt(hasDescendant(FreeCall)))))).bind("if_stmt"), this);


  Finder->addMatcher(
      memberExpr(hasParent(binaryOperator(hasOperatorName("="),hasLHS(declRefExpr(to(varDecl().bind("assigned_ptr")))),hasRHS(declRefExpr(to(varDecl().bind("freed_ptr"))))))).bind("use_after_free_assignment"), this);

  Finder->addMatcher(
      memberExpr(hasParent(binaryOperator(hasOperatorName("="),hasLHS(declRefExpr(to(varDecl().bind("assigned_ptr")))),hasRHS(implicitCastExpr(hasSourceExpression(declRefExpr(to(varDecl().bind("freed_ptr"))))))))).bind("use_after_free_assignment"), this);


  Finder->addMatcher(
      callExpr(hasAnyArgument(declRefExpr(to(varDecl().bind("freed_ptr"))))).bind("use_after_free_call"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  if (const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt")) {
    if (const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call")) {
      if (const auto *FreedPtrDecl = Result.Nodes.getNodeAs<VarDecl>("freed_ptr")) {
        if (const auto *MatchedCallExpr = Result.Nodes.getNodeAs<CallExpr>("of_changeset_add_property_call")) {
            diag(MatchedCallExpr->getBeginLoc(), "Potential use-after-free vulnerability: 'of_changeset_add_property' failed, '%0' freed and potentially used in the next line.")
                << FreedPtrDecl;
        }
      }
    }
  }
  if (const auto *UseAfterFreeAssignment = Result.Nodes.getNodeAs<MemberExpr>("use_after_free_assignment")) {
    if (const auto *FreedPtrDecl = Result.Nodes.getNodeAs<VarDecl>("freed_ptr")) {
        diag(UseAfterFreeAssignment->getBeginLoc(), "Potential use-after-free vulnerability: pointer '%0' is used after being freed.")
            << FreedPtrDecl;
    }
  }

  if (const auto *UseAfterFreeCall = Result.Nodes.getNodeAs<CallExpr>("use_after_free_call")) {
    if (const auto *FreedPtrDecl = Result.Nodes.getNodeAs<VarDecl>("freed_ptr")) {
      diag(UseAfterFreeCall->getBeginLoc(), "Potential use-after-free vulnerability: pointer '%0' is used as an argument after being freed.")
          << FreedPtrDecl;
    }
  }
}

} // namespace clang::tidy::linuxkernel