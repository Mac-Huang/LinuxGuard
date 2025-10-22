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
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )) ,
                          hasRHS(integerLiteral(equals(0)))
                      ),
                      binaryOperator(
                          hasOperatorName("<") ,
                          hasLHS(ignoringParenCasts(
                              callExpr(callee(functionDecl(hasName("of_changeset_add_property"))))
                          )) ,
                          hasRHS(integerLiteral(equals(0)))
                      )
                  )
              )
          ),
          hasThen(
              compoundStmt(
                  hasDescendant(
                      callExpr(
                          callee(functionDecl(hasName("__of_prop_free"))),
                          hasArgument(0, hasDescendant(declRefExpr(to(varDecl(hasName("new_pp"))))))
                      ).bind("free_call")
                  )
              ).bind("then_block")
          ),
          unless(hasThen(compoundStmt(hasDescendant(returnStmt()))))
      ).bind("if_stmt"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
    const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt");
    if (!IfStmt)
        return;

    const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call");
    if (!FreeCall)
        return;

    const auto *ThenBlock = Result.Nodes.getNodeAs<CompoundStmt>("then_block");
    if (!ThenBlock)
        return;
    
    // Find the next statement after the if-statement
    const Stmt *NextStmt = IfStmt->getNextDeclInContext();
    if (!NextStmt) {
        return;
    }

    // Check if the next statement dereferences new_pp
    if (isa<BinaryOperator>(NextStmt)) {
        if (NextStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
            if (NextStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                diag(NextStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
            }
        }
    } else if (isa<UnaryOperator>(NextStmt)) {
        if (NextStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
            if (NextStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                diag(NextStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
            }
        }
    } else if (isa<CallExpr>(NextStmt)) {
        if (NextStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
            if (NextStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                diag(NextStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
            }
        }
    } else if (isa<MemberExpr>(NextStmt)) {
        if (NextStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
            if (NextStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                diag(NextStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
            }
        }
    } else if (isa<CompoundStmt>(NextStmt)) {
        for(const auto *subStmt : NextStmt->children()) {
            if (isa<BinaryOperator>(subStmt)) {
                if (subStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
                    if (subStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                        diag(subStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
                    }
                }
            } else if (isa<UnaryOperator>(subStmt)) {
                if (subStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
                    if (subStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                        diag(subStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
                    }
                }
            } else if (isa<CallExpr>(subStmt)) {
                if (subStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
                    if (subStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                        diag(subStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
                    }
                }
            } else if (isa<MemberExpr>(subStmt)) {
                if (subStmt->getBeginLoc() > ThenBlock->getBeginLoc()) {
                    if (subStmt->contains(declRefExpr(to(varDecl(hasName("new_pp")))))) {
                        diag(subStmt->getBeginLoc(), "potential use-after-free of 'new_pp'");
                    }
                }
            }

        }

    }
}

} // namespace clang::tidy::linuxkernel