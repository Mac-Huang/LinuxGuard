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
  // Match calls to cancel_delayed_work(&ocelot->stats_work) within ocelot_stats_deinit
  auto CancelDelayedWorkCall = callExpr(
      callee(functionDecl(hasName("cancel_delayed_work"))),
      hasArgument(
          0,
          memberExpr(member(hasName("stats_work")),
                     member(hasName("ocelot")))));

  auto DestroyWorkqueueCall = callExpr(
      callee(functionDecl(hasName("destroy_workqueue"))),
      hasArgument(
          0,
          memberExpr(member(hasName("stats_queue")),
                     member(hasName("ocelot")))));


  auto OcelotStatsDeinitFunc = functionDecl(
      hasName("ocelot_stats_deinit"),
      hasBody(compoundStmt(
          has(CancelDelayedWorkCall),
          has(DestroyWorkqueueCall)
      )));

  Finder->addMatcher(OcelotStatsDeinitFunc.bind("ocelot_stats_deinit_func"), this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  if (const auto *FuncDecl = Result.Nodes.getNodeAs<FunctionDecl>("ocelot_stats_deinit_func")) {
    diag(FuncDecl->getBeginLoc(), "Potential use-after-free detected.  `cancel_delayed_work` followed by `destroy_workqueue` in `ocelot_stats_deinit`.  Consider using `disable_delayed_work_sync` instead of `cancel_delayed_work`.")
        << FuncDecl;
  }
}

} // namespace clang::tidy::linuxkernel