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
              expr(
                  anyOf(
                      binaryOperator(
                          hasOperatorName("!=") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property")))).bind("call_of_changeset"))),
                          hasRHS(integerLiteral(equals(0)))
                      ),
                      binaryOperator(
                          hasOperatorName("<") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property")))).bind("call_of_changeset"))),
                          hasRHS(integerLiteral(equals(0)))
                      )
                  )
              )
          ),
          hasThen(
              compoundStmt(
                  hasDescendant(
                      callExpr(callee(functionDecl(hasName("__of_prop_free"))),
                               hasArgument(0, hasDescendant(declRefExpr(to(varDecl(hasType(pointerType().bind("ptr_type"))).bind("freed_ptr"))))))
                          .bind("free_call")
                  )
              ).bind("then_block")
          ),
          unless(hasThen(
              compoundStmt(
                  hasDescendant(returnStmt())
              )
          ))
      )
      .bind("if_stmt"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
  const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
  if (!IfStmt)
    return;

  const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
  if (!FreeCall)
    return;

  const auto *FreedPtrDecl = Result.Nodes.getNodeAs<VarDecl>("freed_ptr");
  if (!FreedPtrDecl)
    return;

  // Find the next statement after the if-statement
  const Stmt *NextStmt = IfStmt->getNextDeclInContext();
  if (!NextStmt) {
    if (const auto *ParentCompoundStmt = dyn_cast<CompoundStmt>(IfStmt->getParent())) {
      const auto &Stmts = ParentCompoundStmt->body();
      for (size_t i = 0; i < Stmts.size(); ++i) {
        if (Stmts[i] == IfStmt) {
          if (i + 1 < Stmts.size()) {
            NextStmt = Stmts[i+1];
            break;
          }
        }
      }
    }
    if (!NextStmt)
      return;
  }
  
  // Check if the freed pointer is used in the next statement.
  if (NextStmt) {
    auto Finder = ast_matchers::MatchFinder();
    auto UseMatcher = anyOf(
        memberExpr(member(hasType(pointerType(pointee(hasType(FreedPtrDecl->getType())))))),
        declRefExpr(to(FreedPtrDecl))
    );
    
    Finder.addMatcher(
      stmt(hasDescendant(UseMatcher))
      .bind("use"),
      this
    );
    
    MatchFinder::MatchResult useResult(Result);
    useResult.Context = &Result.Context->copy();
    useResult.Nodes.setContext(Result.Context);
    
    if (Finder.matches(NextStmt, *useResult.Context).size() > 0)
    {
      const auto *UseNode = useResult.Nodes.getNodeAs<Stmt>("use");
      if(UseNode) {
          diag(UseNode->getBeginLoc(), "use-after-free detected")
              << FreedPtrDecl;
      }
    }
  }
}

} // namespace clang::tidy::linuxkernel