/*
 * Copyright (c) 2017, 2019, Oracle and/or its affiliates.
 * Copyright (c) 2013, Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.oracle.graal.python.nodes.expression;

import static com.oracle.graal.python.nodes.SpecialMethodNames.__EQ__;
import static com.oracle.graal.python.nodes.SpecialMethodNames.__NE__;
import static com.oracle.graal.python.runtime.exception.PythonErrorType.TypeError;

import com.oracle.graal.python.builtins.objects.PNotImplemented;
import com.oracle.graal.python.nodes.PRaiseNode;
import com.oracle.graal.python.nodes.call.special.LookupAndCallBinaryNode;
import com.oracle.truffle.api.CompilerAsserts;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.dsl.Specialization;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.UnexpectedResultException;
import com.oracle.truffle.api.profiles.ConditionProfile;

public abstract class BinaryComparisonNode extends BinaryOpNode {

    protected final String magicMethod;
    protected final String magicReverseMethod;
    private final String operation;
    protected final ConditionProfile profile = ConditionProfile.createBinaryProfile();

    @Child private LookupAndCallBinaryNode callNode;
    @Child private CastToBooleanNode castToBoolean;
    @Child private PRaiseNode raiseNode;

    BinaryComparisonNode(String magicMethod, String magicReverseMethod, String operation) {
        this.magicMethod = magicMethod;
        this.magicReverseMethod = magicReverseMethod;
        this.operation = operation;
        this.callNode = LookupAndCallBinaryNode.create(magicMethod, magicReverseMethod);
    }

    public static BinaryComparisonNode create(String magicMethod, String magicReverseMethod, String operation, ExpressionNode left, ExpressionNode right) {
        return BinaryComparisonNodeGen.create(magicMethod, magicReverseMethod, operation, left, right);
    }

    public static BinaryComparisonNode create(String magicMethod, String magicReverseMethod, String operation) {
        return create(magicMethod, magicReverseMethod, operation, null, null);
    }

    public abstract boolean executeBool(VirtualFrame frame, Object left, Object right);

    private Object handleNotImplemented(Object left, Object right) {
        // just like python, if no implementation is available, do something sensible for
        // == and !=
        if (magicMethod == __EQ__) {
            return left == right;
        } else if (magicMethod == __NE__) {
            return left != right;
        } else {
            if (raiseNode == null) {
                CompilerDirectives.transferToInterpreterAndInvalidate();
                raiseNode = insert(PRaiseNode.create());
            }
            throw raiseNode.raise(TypeError, "'%s' not supported between instances of '%p' and '%p'", operation, left, right);
        }
    }

    private static int asInt(boolean left) {
        return left ? 1 : 0;
    }

    private static double asDouble(boolean left) {
        return left ? 1.0 : 0.0;
    }

    private boolean profileCondition(boolean value) {
        return profile.profile(value);
    }

    private UnexpectedResultException handleUnexpectedResult(VirtualFrame frame, Object result, Object left, Object right) throws UnexpectedResultException {
        CompilerAsserts.neverPartOfCompilation();
        if (castToBoolean == null) {
            castToBoolean = insert(CastToBooleanNode.createIfTrueNode());
        }
        Object value;
        if (result == PNotImplemented.NOT_IMPLEMENTED) {
            value = handleNotImplemented(left, right);
        } else {
            value = castToBoolean.executeBoolean(frame, result);
        }
        throw new UnexpectedResultException(value);
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doBB(VirtualFrame frame, boolean left, boolean right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doBI(VirtualFrame frame, boolean left, int right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, asInt(left), right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doBL(VirtualFrame frame, boolean left, long right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, asInt(left), right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doBD(VirtualFrame frame, boolean left, double right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, asDouble(left), right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doIB(VirtualFrame frame, int left, boolean right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, asInt(right)));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doII(VirtualFrame frame, int left, int right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doIL(VirtualFrame frame, int left, long right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doID(VirtualFrame frame, int left, double right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doLB(VirtualFrame frame, long left, boolean right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, asInt(right)));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doLI(VirtualFrame frame, long left, int right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doLI(VirtualFrame frame, long left, long right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doLI(VirtualFrame frame, long left, double right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doDB(VirtualFrame frame, double left, boolean right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, asDouble(right)));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doDI(VirtualFrame frame, double left, int right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doDL(VirtualFrame frame, double left, long right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization(rewriteOn = UnexpectedResultException.class)
    boolean doDD(VirtualFrame frame, double left, double right) throws UnexpectedResultException {
        try {
            return profileCondition(callNode.executeBool(frame, left, right));
        } catch (UnexpectedResultException e) {
            throw handleUnexpectedResult(frame, e.getResult(), left, right);
        }
    }

    @Specialization
    Object doGeneric(VirtualFrame frame, Object left, Object right) {
        Object result = callNode.executeObject(frame, left, right);
        if (result == PNotImplemented.NOT_IMPLEMENTED) {
            return handleNotImplemented(left, right);
        }
        return result;
    }
}
