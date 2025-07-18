//===--- ap_fallback_000Checker.cpp - Fallback Input Validation Pattern checker -------*- C++ -*-===//
//
// Part of LinuxGuard Static Analysis Framework
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ParentMapContext.h"

using namespace clang;
using namespace ento;

namespace {
class Apfallback000Checker : public Checker<check::PreCall, check::PostCall> {
private:
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

private:
  void reportBug(const CallEvent &Call, CheckerContext &C,
                StringRef Description, SourceRange SR) const;
  bool isTargetFunction(const CallEvent &Call) const;
  bool detectAntiPattern(const CallEvent &Call, CheckerContext &C) const;
};

// Helper class to traverse the AST and find specific patterns.
class FallbackPatternVisitor : public RecursiveASTVisitor<FallbackPatternVisitor> {
public:
  FallbackPatternVisitor(const Stmt *S, ASTContext &Ctx, bool &Found)
      : CurrentStmt(S), Context(Ctx), PatternFound(Found) {}

  bool VisitIfStmt(IfStmt *S) {
    // Check if the 'if' statement condition checks for an error after a function call
    Expr *Cond = S->getCond();
    Stmt *Then = S->getThen();

    if (Cond && Then) {
      // Check for a pattern like: if (function_call() == ERROR_CODE) { ... }
      if (auto *BO = dyn_cast<BinaryOperator>(Cond)) {
        if (BO->getOpcode() == BO_EQ || BO->getOpcode() == BO_NE) {
          if (auto *CallExpr = dyn_cast<CallExpr>(BO->getLHS())) {
              // check if function that can return an error
            if (BO->getRHS()->getType()->isIntegerType() && BO->getLHS()->getType()->isIntegerType()) {
              // The condition checks for an error code.  Now check the 'then' block
              // for a simple error handling and potential fallback to a default value
              // without proper input sanitization on the fallback value.

              // Look for assignments to variables that might be used in a subsequent vulnerable function call
              // inside the "then" block.

              class AssignmentVisitor : public RecursiveASTVisitor<AssignmentVisitor> {
                public:
                  AssignmentVisitor(Stmt *ThenStmt, ASTContext &Ctx, bool &AssignFound, SourceRange &ThenSR)
                  : ThenStmt(ThenStmt), Context(Ctx), AssignmentFound(AssignFound), RangeThen(ThenSR) {}


                bool VisitBinaryOperator(BinaryOperator *BO) {
                    if (BO->isAssignmentOp()) {
                      //assignment detected
                      if( ThenStmt->getSourceRange().contains(BO->getLHS()->getSourceRange())){
                        AssignmentFound = true;
                        RangeThen = BO->getLHS()->getSourceRange(); //Range of assignment
                      }
                    }

                    return true;
                }

                private:
                  Stmt *ThenStmt;
                  ASTContext &Context;
                  bool &AssignmentFound;
                  SourceRange &RangeThen;
              };

              bool AssignFound = false;
              SourceRange RangeThen;
              AssignmentVisitor AV(Then, Context, AssignFound, RangeThen);
              AV.TraverseStmt(Then);


              if (AssignFound) {
                  PatternFound = true;
                  ThenSR = RangeThen;
              }

            }
          }
        }
      }
    }
    return true;
  }

  SourceRange ThenSR;


private:
  const Stmt *CurrentStmt;
  ASTContext &Context;
  bool &PatternFound;
};
} // end anonymous namespace

// Implementation methods here...

void Apfallback000Checker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // Pre-call analysis
  if (!isTargetFunction(Call))
    return;

  if (detectAntiPattern(Call, C)) {
    reportBug(Call, C, "Fallback pattern for input_validation vulnerabilities",SR);
  }
}

void Apfallback000Checker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  // Post-call analysis if needed
}

bool Apfallback000Checker::isTargetFunction(const CallEvent &Call) const {
  // Function matching logic
  const FunctionDecl *FD = Call.getDecl();
  if (!FD)
    return false;

  StringRef FuncName = FD->getName();
  // Add specific function patterns based on the anti-pattern
  // Example: Targets functions that often perform input validation or error handling
  return FuncName == "copy_from_user" || FuncName == "sys_open" || FuncName == "__kmalloc";
}


SourceRange SR;

bool Apfallback000Checker::detectAntiPattern(const CallEvent &Call, CheckerContext &C) const {
  // Anti-pattern detection logic
  // Implement based on detection rules

  // Example: Look for a sequence where a function call's return value is checked for an error,
  // and if an error occurs, a fallback assignment is performed, potentially without
  // sanitizing the fallback value.
  //
  // Code Example:
  //
  // int ret = copy_from_user(&size, arg, sizeof(size));
  // if (ret) {
  //   size = DEFAULT_SIZE; // Potential fallback without sanitization
  // }
  // kmalloc(size, GFP_KERNEL);  // Use size without checking if it came from user space or the default.

  const Stmt *S = Call.getSourceStmt();

  if (!S)
    return false;

  bool PatternFound = false;
  FallbackPatternVisitor Visitor(S, C.getASTContext(), PatternFound);
  Visitor.TraverseStmt(const_cast<Stmt*>(S));
  SR = Visitor.ThenSR;
  return PatternFound;
}

void Apfallback000Checker::reportBug(const CallEvent &Call, CheckerContext &C,
                                    StringRef Description, SourceRange SR) const {
  if (!BT)
    BT.reset(new BugType(this, "Fallback Input Validation Pattern", "other"));

  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;

  auto R = std::make_unique<PathSensitiveBugReport>(*BT, Description, N);
  R->addRange(Call.getSourceRange()); //Range of the function call
  R->addRange(SR); //Range of Assignment
  C.emitReport(std::move(R));
}

// Registration
void ento::registerApfallback000Checker(CheckerManager &mgr) {
  mgr.registerChecker<Apfallback000Checker>();
}

bool ento::shouldRegisterApfallback000Checker(const CheckerManager &mgr) {
  return true;
}