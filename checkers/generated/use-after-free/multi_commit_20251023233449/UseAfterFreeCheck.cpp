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
#include "clang/Basic/SourceManager.h"

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {

void UseAfterFreeCheck::registerMatchers(MatchFinder *Finder) {
  // Match kfree/free function calls
  auto FreeFunction = callExpr(callee(functionDecl(hasAnyName("kfree", "free")))).bind("freeCall");

  // Match access to a pointer after a free call.  This is a simplified example
  // and would need to be expanded to handle more complex scenarios.

  auto Dereference = unaryOperator(
      anyOf(
          hasOperatorName("*"),
          hasOperatorName("->")
      ),
      hasUnaryOperand(
          hasType(pointerType())
      )
  ).bind("dereference");

  auto MemberAccess = memberExpr().bind("memberAccess");

  auto CallWithArg = callExpr(
      anyOf(
          hasArgument(0, hasType(pointerType())),
          hasArgument(1, hasType(pointerType())),
          hasArgument(2, hasType(pointerType()))
      )
  ).bind("callWithArg");


  auto PotentialUseAfterFree =
      anyOf(Dereference, MemberAccess, CallWithArg);


  auto CheckAfterFree = anyOf(
      compoundStmt(
          hasDescendant(FreeFunction),
          hasDescendant(PotentialUseAfterFree)
      ).bind("compoundStmt"),
      ifStmt(
          hasDescendant(FreeFunction),
          hasDescendant(PotentialUseAfterFree)
      ).bind("ifStmt")
  );

  Finder->addMatcher(CheckAfterFree, this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("freeCall");
  if (!FreeCall) {
    return;
  }
  const SourceLocation FreeLoc = FreeCall->getBeginLoc();

  if (const auto *Compound = Result.Nodes.getNodeAs<CompoundStmt>("compoundStmt")) {
    diag(Compound->getBeginLoc(), "Potential use-after-free detected")
        << FreeLoc;
  }
  if (const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("ifStmt")) {
    diag(IfStmt->getBeginLoc(), "Potential use-after-free detected")
        << FreeLoc;
  }
}

} // namespace clang::tidy::linuxkernel