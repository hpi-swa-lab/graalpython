/*
 * Copyright (c) 2017, 2019, Oracle and/or its affiliates.
 * Copyright (c) 2014, Regents of the University of California
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

package com.oracle.graal.python.builtins.objects.method;

import static com.oracle.graal.python.nodes.SpecialAttributeNames.__DOC__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__FUNC__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__MODULE__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__NAME__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__SELF__;
import static com.oracle.graal.python.nodes.SpecialMethodNames.__CALL__;
import static com.oracle.graal.python.nodes.SpecialMethodNames.__EQ__;

import java.util.List;

import com.oracle.graal.python.builtins.Builtin;
import com.oracle.graal.python.builtins.CoreFunctions;
import com.oracle.graal.python.builtins.PythonBuiltinClassType;
import com.oracle.graal.python.builtins.PythonBuiltins;
import com.oracle.graal.python.builtins.modules.BuiltinFunctions.GetAttrNode;
import com.oracle.graal.python.builtins.objects.PNone;
import com.oracle.graal.python.builtins.objects.function.PKeyword;
import com.oracle.graal.python.builtins.objects.module.PythonModule;
import com.oracle.graal.python.builtins.objects.object.PythonObject;
import com.oracle.graal.python.nodes.argument.positional.PositionalArgumentsNode;
import com.oracle.graal.python.nodes.attributes.ReadAttributeFromObjectNode;
import com.oracle.graal.python.nodes.attributes.WriteAttributeToObjectNode;
import com.oracle.graal.python.nodes.call.special.LookupAndCallBinaryNode;
import com.oracle.graal.python.nodes.function.PythonBuiltinBaseNode;
import com.oracle.graal.python.nodes.function.PythonBuiltinNode;
import com.oracle.graal.python.nodes.function.builtins.PythonBinaryBuiltinNode;
import com.oracle.graal.python.nodes.function.builtins.PythonVarargsBuiltinNode;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.dsl.Cached;
import com.oracle.truffle.api.dsl.Fallback;
import com.oracle.truffle.api.dsl.GenerateNodeFactory;
import com.oracle.truffle.api.dsl.NodeFactory;
import com.oracle.truffle.api.dsl.Specialization;
import com.oracle.truffle.api.frame.VirtualFrame;

@CoreFunctions(extendClasses = {PythonBuiltinClassType.PMethod, PythonBuiltinClassType.PBuiltinMethod})
public class AbstractMethodBuiltins extends PythonBuiltins {

    @Override
    protected List<? extends NodeFactory<? extends PythonBuiltinBaseNode>> getNodeFactories() {
        return AbstractMethodBuiltinsFactory.getFactories();
    }

    @Builtin(name = __CALL__, minNumOfPositionalArgs = 1, takesVarArgs = true, takesVarKeywordArgs = true)
    @GenerateNodeFactory
    public abstract static class CallNode extends PythonVarargsBuiltinNode {
        @Child private com.oracle.graal.python.nodes.call.CallNode callNode = com.oracle.graal.python.nodes.call.CallNode.create();

        @Specialization(guards = "isFunction(self.getFunction())")
        protected Object doIt(VirtualFrame frame, PMethod self, Object[] arguments, PKeyword[] keywords) {
            return callNode.execute(frame, self, arguments, keywords);
        }

        @Specialization(guards = "isFunction(self.getFunction())")
        protected Object doIt(VirtualFrame frame, PBuiltinMethod self, Object[] arguments, PKeyword[] keywords) {
            return callNode.execute(frame, self, arguments, keywords);
        }

        @Specialization(guards = "!isFunction(self.getFunction())")
        protected Object doItNonFunction(VirtualFrame frame, PMethod self, Object[] arguments, PKeyword[] keywords) {
            return callNode.execute(frame, self.getFunction(), PositionalArgumentsNode.prependArgument(self.getSelf(), arguments), keywords);
        }

        @Specialization(guards = "!isFunction(self.getFunction())")
        protected Object doItNonFunction(VirtualFrame frame, PBuiltinMethod self, Object[] arguments, PKeyword[] keywords) {
            return callNode.execute(frame, self.getFunction(), PositionalArgumentsNode.prependArgument(self.getSelf(), arguments), keywords);
        }

        @Override
        public Object varArgExecute(VirtualFrame frame, Object[] arguments, PKeyword[] keywords) throws VarargsBuiltinDirectInvocationNotSupported {
            Object[] argsWithoutSelf = new Object[arguments.length - 1];
            System.arraycopy(arguments, 1, argsWithoutSelf, 0, argsWithoutSelf.length);
            return execute(frame, arguments[0], argsWithoutSelf, keywords);
        }
    }

    @Builtin(name = __SELF__, minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    public abstract static class SelfNode extends PythonBuiltinNode {
        @Specialization
        protected Object doIt(PMethod self) {
            return self.getSelf();
        }

        @Specialization
        protected Object doIt(PBuiltinMethod self) {
            return self.getSelf();
        }
    }

    @Builtin(name = __FUNC__, minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    public abstract static class FuncNode extends PythonBuiltinNode {
        @Specialization
        protected Object doIt(PMethod self) {
            return self.getFunction();
        }

        @Specialization
        protected Object doIt(PBuiltinMethod self) {
            return self.getFunction();
        }
    }

    @Builtin(name = __NAME__, minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    public abstract static class NameNode extends PythonBuiltinNode {
        @Specialization
        protected Object doIt(VirtualFrame frame, PMethod self,
                        @Cached("create(__GETATTRIBUTE__)") LookupAndCallBinaryNode getName) {
            return getName.executeObject(frame, self.getFunction(), __NAME__);
        }

        @Specialization
        protected Object doIt(VirtualFrame frame, PBuiltinMethod self,
                        @Cached("create(__GETATTRIBUTE__)") LookupAndCallBinaryNode getName) {
            return getName.executeObject(frame, self.getFunction(), __NAME__);
        }
    }

    @Builtin(name = __EQ__, minNumOfPositionalArgs = 2)
    @GenerateNodeFactory
    abstract static class EqNode extends PythonBinaryBuiltinNode {
        @Specialization
        boolean eq(PMethod self, PMethod other) {
            return self.getFunction() == other.getFunction() && self.getSelf() == other.getSelf();
        }

        @Specialization
        boolean eq(PBuiltinMethod self, PBuiltinMethod other) {
            return self.getFunction() == other.getFunction() && self.getSelf() == other.getSelf();
        }

        @Fallback
        boolean eq(@SuppressWarnings("unused") Object self, @SuppressWarnings("unused") Object other) {
            return false;
        }
    }

    @Builtin(name = __MODULE__, minNumOfPositionalArgs = 1, maxNumOfPositionalArgs = 2, isGetter = true, isSetter = true)
    @GenerateNodeFactory
    abstract static class GetModuleNode extends PythonBuiltinNode {
        @Specialization(guards = "isNoValue(none)")
        Object getModule(VirtualFrame frame, PythonObject self, @SuppressWarnings("unused") PNone none,
                        @Cached("create()") ReadAttributeFromObjectNode readObject,
                        @Cached("create()") GetAttrNode getAttr,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            Object module = readObject.execute(self, __MODULE__);
            if (module == PNone.NO_VALUE) {
                CompilerDirectives.transferToInterpreter();
                Object globals = self instanceof PMethod ? ((PMethod) self).getSelf() : ((PBuiltinMethod) self).getSelf();
                if (globals instanceof PythonModule) {
                    module = ((PythonModule) globals).getAttribute(__NAME__);
                } else {
                    module = getAttr.execute(frame, globals, __MODULE__, PNone.NONE);
                }
                writeObject.execute(self, __MODULE__, module);
            }
            return module;
        }

        @Specialization(guards = {"!isBuiltinMethod(self)", "!isNoValue(value)"})
        Object getModule(PythonObject self, Object value,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            writeObject.execute(self, __MODULE__, value);
            return PNone.NONE;
        }

        @Specialization(guards = "!isNoValue(value)")
        Object getModule(PBuiltinMethod self, Object value) {
            CompilerDirectives.transferToInterpreter();
            self.getStorage().define(__MODULE__, value);
            return PNone.NONE;
        }
    }

    @Builtin(name = __DOC__, minNumOfPositionalArgs = 1, maxNumOfPositionalArgs = 2, isGetter = true, isSetter = true)
    @GenerateNodeFactory
    abstract static class DocNode extends PythonBinaryBuiltinNode {
        @Child ReadAttributeFromObjectNode readFunc;

        private Object readFromFunc(Object func) {
            if (readFunc == null) {
                CompilerDirectives.transferToInterpreterAndInvalidate();
                readFunc = insert(ReadAttributeFromObjectNode.create());
            }
            Object doc = readFunc.execute(func, __DOC__);
            if (doc == PNone.NO_VALUE) {
                doc = PNone.NONE;
            }
            return doc;
        }

        @Specialization(guards = "isNoValue(none)")
        Object getModule(PMethod self, @SuppressWarnings("unused") PNone none,
                        @Cached("create()") ReadAttributeFromObjectNode readSelf) {
            Object doc = readSelf.execute(self, __DOC__);
            if (doc == PNone.NO_VALUE) {
                return readFromFunc(self.getFunction());
            }
            return doc;
        }

        @Specialization(guards = "isNoValue(none)")
        Object getModule(PBuiltinMethod self, @SuppressWarnings("unused") PNone none,
                        @Cached("create()") ReadAttributeFromObjectNode readSelf) {
            Object doc = readSelf.execute(self, __DOC__);
            if (doc == PNone.NO_VALUE) {
                return readFromFunc(self.getFunction());
            }
            return doc;
        }

        @Specialization(guards = {"!isNoValue(value)"})
        Object getModule(PMethod self, Object value,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            writeObject.execute(self, __DOC__, value);
            return PNone.NONE;
        }

        @Specialization(guards = {"!isNoValue(value)"})
        Object getModule(@SuppressWarnings("unused") PBuiltinMethod self, @SuppressWarnings("unused") Object value) {
            throw raise(PythonBuiltinClassType.AttributeError, "attribute '__doc__' of 'builtin_function_or_method' objects is not writable");
        }
    }
}
