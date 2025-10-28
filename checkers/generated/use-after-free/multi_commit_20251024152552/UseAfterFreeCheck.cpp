//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UseAfterFreeCheck.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {

void UseAfterFreeCheck::registerMatchers(MatchFinder *Finder) {
  // Matcher for kfree and similar functions.
  auto FreeFunction = functionDecl(hasAnyName("kfree", "devlink_free", "destroy_workqueue"));
  auto FreeCall = callExpr(callee(FreeFunction)).bind("free_call");

  // Matcher for accessing an object member after a potential free operation.  This is a simplified example.
  // The actual pattern needs more context (e.g., specific struct members, variable names, etc. that vary by commit).
  auto MemberAccessAfterFree = memberExpr(member(hasType(pointsTo(anything())))).bind("member_access");

  // Matcher for cancel_delayed_work and similar functions.
  auto CancelWorkFunction = functionDecl(hasAnyName("cancel_delayed_work", "wiphy_delayed_work_queue"));
  auto CancelWorkCall = callExpr(callee(CancelWorkFunction)).bind("cancel_call");

    // Matcher for function calls that schedule/queue work items.
    auto ScheduleWorkFunction = functionDecl(hasAnyName("schedule_work", "queue_work"));
    auto ScheduleWorkCall = callExpr(callee(ScheduleWorkFunction)).bind("schedule_call");

    // Matcher for of_changeset_add_property.
    auto OfChangesetAddPropertyCall = callExpr(callee(functionDecl(hasName("of_changeset_add_property")))).bind("of_changeset_add_property_call");
    // Matcher for __of_prop_free.
    auto OfPropFreeCall = callExpr(callee(functionDecl(hasName("__of_prop_free")))).bind("of_prop_free_call");

  // General pattern:  Free call followed by access (simplified).  This is very basic; the real check needs more.
  Finder->addMatcher(
      allOf(
          FreeCall,
          hasAncestor(compoundStmt(hasDescendant(MemberAccessAfterFree)).bind("parent_block"))),
      this);

    // devlink_free at the end of function
    auto DevlinkFreeAtEndOfFunction =
            allOf(
                    FreeCall,
                    hasAncestor(functionDecl().bind("devlink_free_function")),
                    isLastInCompoundStatement()
            );
    Finder->addMatcher(DevlinkFreeAtEndOfFunction, this);

    // Check for accesses to connection object (conn) members after it could have been freed, and check connection's state before performing operations
    // This is a placeholder for the more complex pattern involving specific struct, members, and state checks
    auto ConnMemberAccessAfterPotentialFree =
            memberExpr(
                    hasBase(
                            expr(hasType(pointsTo(recordDecl(hasName("connection_struct")))))  //Replace connection_struct with actual struct name if known
                    ).bind("conn_member"),
                    hasAncestor(compoundStmt(hasDescendant(callExpr(callee(FreeFunction))))).bind("parent_compound_stmt")
            );

    Finder->addMatcher(ConnMemberAccessAfterPotentialFree, this);

    //Verify that redundant calls to of_node_put are removed inside for loops with for_each_child_of_node
    auto OfNodePutCall = callExpr(callee(functionDecl(hasName("of_node_put")))).bind("of_node_put_call");
    auto ForEachChildOfNodeLoop = forStmt(hasLoopInit(declStmt(hasDescendant(varDecl(hasType(pointsTo(qualType(hasDeclaration(recordDecl(hasName("of_node")))))))))),
                                            hasBody(compoundStmt(hasDescendant(OfNodePutCall)))
                                       ).bind("for_each_loop");

    Finder->addMatcher(ForEachChildOfNodeLoop, this);


    //Match READ_ONCE(q->task) before wake_up_state(task, TASK_NORMAL);
    auto ReadOnceTaskAccess = memberExpr(hasBase(declRefExpr(to(varDecl(hasType(pointsTo(qualType(hasDeclaration(recordDecl(hasName("work_struct")))))))))) , hasName("task"));  // Match `q->task` type access
    auto ReadOnceCall = callExpr(callee(functionDecl(hasName("READ_ONCE"))), hasArgument(0, ReadOnceTaskAccess)).bind("read_once_call");

    auto WakeUpStateCall = callExpr(callee(functionDecl(hasName("wake_up_state"))), hasArgument(0, declRefExpr(to(varDecl(hasType(pointsTo(qualType(hasDeclaration(recordDecl(hasName("task_struct")))))))))))
                           .bind("wake_up_call");

    Finder->addMatcher(compoundStmt(hasDescendant(ReadOnceCall), hasDescendant(WakeUpStateCall)).bind("compound_stmt"), this);


    // General pattern:  cancel_delayed_work followed by use (simplified).
    Finder->addMatcher(
        allOf(
            CancelWorkCall,
            hasAncestor(compoundStmt(hasDescendant(MemberAccessAfterFree)).bind("parent_block"))),
        this);

    // General pattern:  schedule_work followed by potential access after a free operation (simplified).
    Finder->addMatcher(
            allOf(
                    ScheduleWorkCall,
                    hasAncestor(compoundStmt(hasDescendant(MemberAccessAfterFree)).bind("parent_block"))
            ),
            this);


    // Check if cancel_delayed_work is called without proper synchronization
    auto CancelWithoutSync =
            allOf(
                    CancelWorkCall,
                    unless(
                            hasAncestor(
                                    compoundStmt(
                                            hasDescendant(callExpr(callee(functionDecl(hasName("disable_delayed_work_sync"))))),
                                            hasDescendant(returnStmt())
                                    ).bind("sync_block")
                            )
                    )
            );
    Finder->addMatcher(CancelWithoutSync, this);


    // Check for of_changeset_add_property followed by of_prop_free.
    Finder->addMatcher(
        allOf(
            OfChangesetAddPropertyCall,
            hasAncestor(compoundStmt(hasDescendant(OfPropFreeCall)))
        ),
        this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  if (const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call")) {
    if (const auto *MemberAccess = Result.Nodes.getNodeAs<MemberExpr>("member_access")) {
      diag(MemberAccess->getExprLoc(), "Potential use-after-free: accessing member after a call to %0")
          << FreeCall->getDirectCallee();
    }
  }

  if (const auto *CancelCall = Result.Nodes.getNodeAs<CallExpr>("cancel_call")) {
    if (const auto *MemberAccess = Result.Nodes.getNodeAs<MemberExpr>("member_access")) {
      diag(MemberAccess->getExprLoc(), "Potential use-after-free: accessing member after a call to cancel_delayed_work")
          << CancelCall->getDirectCallee();
    }
  }

    if (const auto *ScheduleCall = Result.Nodes.getNodeAs<CallExpr>("schedule_call")) {
        if (const auto *MemberAccess = Result.Nodes.getNodeAs<MemberExpr>("member_access")) {
            diag(MemberAccess->getExprLoc(), "Potential use-after-free: accessing member after a call to schedule_work")
                    << ScheduleCall->getDirectCallee();
        }
    }

    if (const auto *FuncDecl = Result.Nodes.getNodeAs<FunctionDecl>("devlink_free_function")) {
        if (const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call")) {
          diag(FreeCall->getExprLoc(), "devlink_free should be called at the end of function body.")
                << FreeCall->getDirectCallee();
        }
    }

    if (const auto *ConnAccess = Result.Nodes.getNodeAs<MemberExpr>("conn_member")) {
        diag(ConnAccess->getExprLoc(), "Potential use-after-free: accessing conn member after potential free.")
                << ConnAccess->getExprLoc();
    }

    if (const auto *ForEachLoop = Result.Nodes.getNodeAs<ForStmt>("for_each_loop")) {
        diag(ForEachLoop->getBeginLoc(), "Redundant call to of_node_put inside for loop, consider removing this.")
            << ForEachLoop->getBeginLoc();
    }

    if (const auto *ReadOnceCall = Result.Nodes.getNodeAs<CallExpr>("read_once_call")) {
        if (Result.Nodes.getNodeAs<CallExpr>("wake_up_call")) {
          diag(ReadOnceCall->getExprLoc(), "Missing READ_ONCE before wake_up_state call");
        }
    }

    if (const auto *CancelWithoutSyncCall = Result.Nodes.getNodeAs<CallExpr>("cancel_call")) {
        diag(CancelWithoutSyncCall->getExprLoc(), "cancel_delayed_work called without proper synchronization or return check")
          << CancelWithoutSyncCall->getDirectCallee();
    }

    if (const auto *OfChangesetCall = Result.Nodes.getNodeAs<CallExpr>("of_changeset_add_property_call")) {
        if (Result.Nodes.getNodeAs<CallExpr>("of_prop_free_call")) {
            diag(OfChangesetCall->getExprLoc(), "of_changeset_add_property call followed by __of_prop_free.")
                << OfChangesetCall->getDirectCallee();
        }
    }
}

} // namespace clang::tidy::linuxkernel