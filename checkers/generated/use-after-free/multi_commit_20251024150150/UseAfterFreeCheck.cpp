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
  // Functions known to free resources.  Add more as needed.
  auto FreeFunction = functionDecl(hasAnyName(
      "kfree", "free", "destroy_workqueue", "unregister_framebuffer",
      "devlink_free", "tb_tunnel_put", "sock_set_flag", "__of_prop_free"));

  // Functions that can lead to use after free. Add more as needed.
  auto UseAfterFreeFunction = functionDecl(hasAnyName(
      "cancel_delayed_work", "simplefb_detach_genpds", "mvs_work_queue",
      "tb_dp_dprx_work", "wake_up_state", "hci_conn_complete_evt",
      "le_conn_complete_evt", "ixgbe_reset_interrupt_capability"));

  // Matcher for freeing a resource
  auto FreeCall = callExpr(callee(FreeFunction)).bind("freeCall");

  // Matcher for a potential use-after-free scenario. This matches a function call
  // that *could* use a freed resource. This is deliberately broad to catch
  // potential issues, and will require further analysis in the check() function.
  auto UseCall = callExpr(callee(UseAfterFreeFunction)).bind("useCall");

  // General pattern:  Free followed by potential use.
  Finder->addMatcher(
      stmt(anyOf(
               // Direct use after free
               allOf(hasDescendant(FreeCall), hasDescendant(UseCall)),
               // Use within the same compound statement as a free.
               compoundStmt(hasDescendant(FreeCall), hasDescendant(UseCall))
               ))
          .bind("potentialUAF"),
      this);

  // Specific check for cancel_delayed_work.
  auto CancelDelayedWorkCall = callExpr(callee(hasName("cancel_delayed_work"))).bind("cancelDelayedWorkCall");
  auto DisableDelayedWorkSyncCall = callExpr(callee(hasName("disable_delayed_work_sync"))).bind("disableDelayedWorkSyncCall");
  auto CancelDelayedWorkSyncCall = callExpr(callee(hasName("cancel_delayed_work_sync"))).bind("cancelDelayedWorkSyncCall");
  auto IfWithCancel = ifStmt(hasDescendant(CancelDelayedWorkCall)).bind("ifWithCancel");
  auto ReturnAfterCancel = returnStmt(hasAncestor(IfWithCancel)).bind("returnAfterCancel");


  // Detect cancel_delayed_work followed by use.
    Finder->addMatcher(
        stmt(anyOf(
                 allOf(hasDescendant(CancelDelayedWorkCall), hasDescendant(UseCall)),
                 compoundStmt(hasDescendant(CancelDelayedWorkCall), hasDescendant(UseCall))
                 ))
        .bind("cancelDelayedWorkUAF"),
        this);

  //Detect missing sync or check
  Finder->addMatcher(
    stmt(allOf(
          hasDescendant(CancelDelayedWorkCall),
          unless(hasDescendant(anyOf(DisableDelayedWorkSyncCall, CancelDelayedWorkSyncCall, IfStmt(hasDescendant(CancelDelayedWorkCall), hasDescendant(returnStmt()))))) // exclude disabling, syncing, or return after cancel
      ))
      .bind("missingSyncOrCheck"),
    this);


  //Specific check for devlink_free
  Finder->addMatcher(
    callExpr(callee(hasName("devlink_free")),
             hasAncestor(compoundStmt(hasDescendant(callExpr(callee(functionDecl(hasAnyName("devlink_get_port"))))))))
      .bind("devlinkFreeTooEarly"),
    this);

    //Specific check for of_node_put within loop.
    Finder->addMatcher(
      callExpr(callee(hasName("of_node_put")),
               hasAncestor(forStmt()))
        .bind("ofNodePutInLoop"),
      this);

    // Check for double frees using a similar approach to the UAF detection, focusing on adjacent free calls with the same argument.  This is a simplified approach and may produce false positives.  A more robust solution would require data flow analysis.
    auto FreeCallWithArg = callExpr(callee(FreeFunction), hasArgument(0, expr().bind("freedArg"))).bind("freeCallWithArg");
    Finder->addMatcher(
        compoundStmt(has(FreeCallWithArg), has(FreeCallWithArg),
                     hasDescendant(expr(equalsBoundNode("freedArg"))))
            .bind("doubleFree"),
        this);
}


void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  if (const auto *PotentialUAF = Result.Nodes.getNodeAs<Stmt>("potentialUAF")) {
    const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("freeCall");
    const auto *UseCall = Result.Nodes.getNodeAs<CallExpr>("useCall");

    if (FreeCall && UseCall) {
      diag(UseCall->getExprLoc(), "Potential use-after-free: Function '%0' may use a resource freed by '%1'")
          << UseCall->getDirectCallee() << FreeCall->getDirectCallee();
    }
  }

  if (const auto *CancelDelayedWorkUAF = Result.Nodes.getNodeAs<Stmt>("cancelDelayedWorkUAF")) {

      const auto *CancelDelayedWorkCall = Result.Nodes.getNodeAs<CallExpr>("cancelDelayedWorkCall");
      const auto *UseCall = Result.Nodes.getNodeAs<CallExpr>("useCall");
      if(CancelDelayedWorkCall && UseCall){
          diag(UseCall->getExprLoc(), "Potential use-after-free after cancel_delayed_work");
          diag(CancelDelayedWorkCall->getExprLoc(), "cancel_delayed_work call here");
      }
  }

  if(const auto *MissingSyncOrCheck = Result.Nodes.getNodeAs<Stmt>("missingSyncOrCheck")){
      const auto *CancelDelayedWorkCall = Result.Nodes.getNodeAs<CallExpr>("cancelDelayedWorkCall");
        if(CancelDelayedWorkCall){
            diag(CancelDelayedWorkCall->getExprLoc(), "Missing synchronization or check after cancel_delayed_work");
        }
  }

  if (const auto *MatchedDevlinkFreeTooEarly =
          Result.Nodes.getNodeAs<CallExpr>("devlinkFreeTooEarly")) {
      diag(MatchedDevlinkFreeTooEarly->getExprLoc(), "Potential use-after-free: devlink_free called before ports are finished with the resource.");
  }


    if (const auto *MatchedOfNodePutInLoop =
          Result.Nodes.getNodeAs<CallExpr>("ofNodePutInLoop")) {
      diag(MatchedOfNodePutInLoop->getExprLoc(), "Potential resource leak: of_node_put called repeatedly inside a loop.");
  }


    if (const auto *DoubleFree = Result.Nodes.getNodeAs<Stmt>("doubleFree")) {
        const auto *SecondFree = Result.Nodes.getNodeAs<CallExpr>("freeCallWithArg");
        if (SecondFree) {
            diag(SecondFree->getExprLoc(), "Potential double-free detected.");
        }
    }
}

} // namespace clang::tidy::linuxkernel