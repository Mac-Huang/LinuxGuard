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
  // Match functions known to free memory
  auto FreeFunction = functionDecl(hasAnyName(
      "kfree", "devlink_free", "tb_tunnel_put", "destroy_workqueue",
      "unregister_framebuffer", "cancel_delayed_work"));

  // Match calls to free functions
  auto FreeCall = callExpr(callee(FreeFunction)).bind("free_call");

  // Match access to memory after free.  This is a simplified example.
  // Real-world checkers would need more sophisticated tracking of pointers
  // and potential aliasing.  This example focuses on direct pointer use
  // after a kfree.
  auto DereferenceAfterFree =
      memberExpr(hasDescendant(
                     unaryOperator(hasOperatorName("*"),
                                   hasDescendant(declRefExpr(to(
                                       varDecl(hasType(pointerType(anything())))))))
                 )).bind("dereference");

  // Combine free and use after free patterns.  The 'UseAfterFree' match needs to be within a compound statement.
  Finder->addMatcher(compoundStmt(hasDescendant(FreeCall), hasDescendant(DereferenceAfterFree)).bind("combined_pattern"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *MatchedCombinedPattern =
      Result.Nodes.getNodeAs<Stmt>("combined_pattern");

  if (MatchedCombinedPattern) {
    const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
    const auto *Dereference = Result.Nodes.getNodeAs<MemberExpr>("dereference");

    if (FreeCall && Dereference) {
      diag(FreeCall->getExprLoc(), "Potential use-after-free vulnerability: Memory freed but possibly accessed later.");
      diag(Dereference->getExprLoc(), "Use of memory after potential free");
    }
  }
}

} // namespace clang::tidy::linuxkernel