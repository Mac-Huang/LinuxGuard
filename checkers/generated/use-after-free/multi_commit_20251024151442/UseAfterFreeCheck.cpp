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
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/SourceManager.h"

using namespace clang::ast_matchers;

namespace clang::tidy::linuxkernel {

void UseAfterFreeCheck::registerMatchers(MatchFinder *Finder) {
  // Match kfree/free function calls
  auto FreeFunc =
      functionDecl(hasAnyName("kfree", "devlink_free", "cancel_delayed_work", "free", "skb_free"));
  auto FreeCall = callExpr(callee(FreeFunc)).bind("free_call");

  // Match the argument of the free function
  auto FreedPointer = expr().bind("freed_pointer");

  // Match access to a field of a potential freed object after the free
  auto MemberAccessAfterFree = memberExpr(member(hasType(pointsTo(qualType(hasDeclaration(varDecl(hasType(pointsTo(anything()))))))))).bind("member_access");

  // General pattern for access after free, also handle dereferences
  auto DerefAfterFree = unaryOperator(hasOperatorName("*"), hasUnaryOperand(expr().bind("deref_operand"))).bind("deref_after_free");


  // Combine free call and subsequent use
  Finder->addMatcher(
      allOf(
          FreeCall,
          has(anyOf(
              hasArgument(0, expr(equalsBoundNode("freed_pointer"))),  // capture the argument passed to free
              hasArgument(0, expr(hasType(pointsTo(anything()))).bind("freed_pointer_in_expr"))  // or if pointer is passed as argument
              )),
          anyOf(
              hasDescendant(MemberAccessAfterFree),
              hasDescendant(DerefAfterFree)
          )
      ),
      this);

    // Specific Pattern 1: hci_conn use after kfree

    auto ConnHashLookupCall = callExpr(callee(functionDecl(hasName("hci_conn_hash_lookup_ba")))).bind("conn_lookup_ba_call");

    auto ConnHashLookupRoleCall = callExpr(callee(functionDecl(hasName("hci_conn_hash_lookup_role")))).bind("conn_lookup_role_call");

    auto IfConnCheck = ifStmt(hasCondition(anyOf(
                                                 unaryOperator(hasOperatorName("!"), hasUnaryOperand(expr(hasType(pointsTo(qualType(hasDeclaration(recordDecl(hasName("hci_conn"))))))).bind("conn"))),
                                                 binaryOperator(hasOperatorName("=="), hasLHS(memberExpr(member(hasName("role")))), hasRHS(integerLiteral(equals(1)))),
                                                 binaryOperator(hasOperatorName("!="), hasLHS(memberExpr(member(hasName("state")))), hasRHS(integerLiteral(equals(1))))
                                                ))
    ).bind("if_conn_check");

    auto ConnMemberAccess = memberExpr(member(hasType(qualType(hasDeclaration(recordDecl(hasName("hci_conn"))))))).bind("conn_member_access");

    Finder->addMatcher(
        allOf(
            anyOf(ConnHashLookupCall, ConnHashLookupRoleCall),
            hasAncestor(IfConnCheck),
            hasAncestor(ConnMemberAccess)
            ),
        this);

    // Specific Pattern 2: skb use after skb_free
    auto SkbFreeCall = callExpr(callee(functionDecl(hasName("skb_free")))).bind("skb_free_call");
    auto SkbMemberAccess = memberExpr(member(hasType(qualType(hasDeclaration(recordDecl(hasName("sk_buff"))))))).bind("skb_member_access");

    Finder->addMatcher(
        allOf(
            SkbFreeCall,
            hasAncestor(SkbMemberAccess)
        ),
        this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  const auto *FreedPointer = Result.Nodes.getNodeAs<Expr>("freed_pointer");
  const auto *FreedPointerInExpr = Result.Nodes.getNodeAs<Expr>("freed_pointer_in_expr");
  const auto *MemberAccess = Result.Nodes.getNodeAs<MemberExpr>("member_access");
  const auto *DerefAfterFree = Result.Nodes.getNodeAs<UnaryOperator>("deref_after_free");
  const auto *IfConnCheck = Result.Nodes.getNodeAs<IfStmt>("if_conn_check");
  const auto *ConnLookupBaCall = Result.Nodes.getNodeAs<CallExpr>("conn_lookup_ba_call");
  const auto *ConnLookupRoleCall = Result.Nodes.getNodeAs<CallExpr>("conn_lookup_role_call");
  const auto *SkbFreeCall = Result.Nodes.getNodeAs<CallExpr>("skb_free_call");
  const auto *SkbMemberAccess = Result.Nodes.getNodeAs<MemberExpr>("skb_member_access");

  SourceLocation DiagLoc;

  if (FreeCall && (FreedPointer || FreedPointerInExpr) && (MemberAccess || DerefAfterFree)) {
      if (MemberAccess)
          DiagLoc = MemberAccess->getExprLoc();
      else if(DerefAfterFree)
          DiagLoc = DerefAfterFree->getExprLoc();

    diag(DiagLoc, "use-after-free: accessing freed memory at %0 after call to %1")
        << (MemberAccess ? cast<Expr>(MemberAccess) : cast<Expr>(DerefAfterFree))
        << FreeCall->getDirectCallee();
  }

  if ((ConnLookupBaCall || ConnLookupRoleCall) && IfConnCheck && ConnMemberAccess) {
      diag(ConnMemberAccess->getExprLoc(), "Potential use-after-free of hci_conn member");
  }

  if (SkbFreeCall && SkbMemberAccess) {
      diag(SkbMemberAccess->getExprLoc(), "Potential use-after-free of skb member");
  }
}

} // namespace clang::tidy::linuxkernel