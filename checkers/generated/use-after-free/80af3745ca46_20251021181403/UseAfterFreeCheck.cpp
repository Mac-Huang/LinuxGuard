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
      ifStmt(hasCondition(binaryOperator(
                  hasOperatorName("!=") ,
                  hasLHS(ignoringParenImpCasts(callExpr(callee(functionDecl(hasName("of_changeset_add_property")))))),
                  hasRHS(integerLiteral(equals(0))))),
             hasThen(compoundStmt(has(callExpr(callee(functionDecl(hasName("__of_prop_free")))).bind("free_call")))),
             hasElse(anything())).bind("if_stmt"),
      this);

  Finder->addMatcher(
      memberExpr(member(hasName("next")),
                 hasObject(ignoringParenImpCasts(declRefExpr(to(varDecl(hasType(pointerType()))).bind("freed_ptr")))),
                 hasParent(binaryOperator(hasOperatorName("="), hasLHS(memberExpr(member(hasName("next"))))))).bind("use_after_free"),
      this);
}

void UseAfterFreeCheck::check(const MatchFinder::MatchResult &Result) {
    if (const auto *IfStmt = Result.Nodes.getNodeAs<IfStmt>("if_stmt")) {
        if (const auto *FreeCall = Result.Nodes.getNodeAs<CallExpr>("free_call")) {
           if(const auto *UseAfterFree = Result.Nodes.getNodeAs<MemberExpr>("use_after_free")) {

            // Check if the freed pointer is used in the same context
            const auto *FreedPtr = Result.Nodes.getNodeAs<DeclRefExpr>("freed_ptr");
               if (FreedPtr) {

                  SourceLocation FreeLoc = FreeCall->getBeginLoc();
                  SourceLocation UseLoc = UseAfterFree->getBeginLoc();
                  SourceLocation IfLoc = IfStmt->getBeginLoc();


                  if(UseLoc.isFileID() && FreeLoc.isFileID() && IfLoc.isFileID()){
                    if (UseLoc.getLocWithOffset(-1).getRawEncoding() > FreeLoc.getLocWithOffset(0).getRawEncoding() && UseLoc.getLocWithOffset(-1).getRawEncoding() < IfStmt->getEndLoc().getRawEncoding()) {
                     diag(UseLoc, "potential use-after-free detected")
                      << SourceRange(FreeCall->getSourceRange());
                    }

                  }
               }
           }
        }
    }
}


} // namespace clang::tidy::linuxkernel