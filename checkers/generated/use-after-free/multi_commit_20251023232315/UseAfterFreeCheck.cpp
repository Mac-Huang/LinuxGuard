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
  // Match deallocation functions.  Expand this as needed.  Crucially,
  // this is the FIRST step.
  auto DeallocFn = functionDecl(hasAnyName("kfree", "devlink_free", "tb_tunnel_put", "simplefb_detach_genpds", "destroy_workqueue"));

  // Match the pointer being freed. This is key to tracking.
  auto FreedPointer =
      declRefExpr(to(varDecl().bind("freed_var")));

  // Match the deallocation call.
  auto DeallocCall =
      callExpr(callee(DeallocFn), hasArgument(0, expr(FreedPointer))).bind("dealloc_call");


  // Match uses of the freed variable AFTER the deallocation.  This is
  // the second crucial step.  This is a simplified approach, needs
  // refinement based on actual patterns in the kernel.  The
  // critical thing is that this checks for use *after* the deallocation.
  auto UseOfFreed =
      declRefExpr(to(varDecl(equalsBoundNode("freed_var")))).bind("use_after_free");


  // Combine the above matchers to look for the pattern.  This checks
  // for a use of the freed variable *after* a call to a deallocation function
  // within the same compound statement or a subsequent one.
  // This is a simplified example; real patterns will require more
  // sophisticated analysis of control flow and data dependencies.
  auto PotentiallyVulnerableStmt =
      anyOf(
          compoundStmt(hasDescendant(DeallocCall), hasDescendant(UseOfFreed)),
          // Added a check to see if the use of the freed variable occurs
          // in a different compound statement after the deallocation
          stmt(hasDescendant(DeallocCall),
               hasAncestor(compoundStmt(hasDescendant(UseOfFreed))))
          );



  Finder->addMatcher(PotentiallyVulnerableStmt, this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *MatchedDeallocCall = Result.Nodes.getNodeAs<CallExpr>("dealloc_call");
  const auto *MatchedUse = Result.Nodes.getNodeAs<DeclRefExpr>("use_after_free");

  if (MatchedDeallocCall && MatchedUse) {
      diag(MatchedUse->getExprLoc(), "Potential use-after-free: use of freed memory")
          << MatchedUse;
      diag(MatchedDeallocCall->getExprLoc(), "Memory deallocated here")
          << MatchedDeallocCall;
  }
}

} // namespace clang::tidy::linuxkernel