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

package com.oracle.graal.python.builtins.objects.function;

import static com.oracle.graal.python.nodes.SpecialAttributeNames.__ANNOTATIONS__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__CLOSURE__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__DICT__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__GLOBALS__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__MODULE__;
import static com.oracle.graal.python.nodes.SpecialAttributeNames.__NAME__;
import static com.oracle.graal.python.nodes.SpecialMethodNames.__CALL__;
import static com.oracle.graal.python.nodes.SpecialMethodNames.__GET__;
import static com.oracle.graal.python.runtime.exception.PythonErrorType.AttributeError;

import java.util.List;

import com.oracle.graal.python.builtins.Builtin;
import com.oracle.graal.python.builtins.CoreFunctions;
import com.oracle.graal.python.builtins.PythonBuiltinClassType;
import com.oracle.graal.python.builtins.PythonBuiltins;
import com.oracle.graal.python.builtins.objects.PNone;
import com.oracle.graal.python.builtins.objects.cell.PCell;
import com.oracle.graal.python.builtins.objects.common.PHashingCollection;
import com.oracle.graal.python.builtins.objects.method.PBuiltinMethod;
import com.oracle.graal.python.builtins.objects.method.PMethod;
import com.oracle.graal.python.builtins.objects.module.PythonModule;
import com.oracle.graal.python.builtins.objects.object.PythonObject;
import com.oracle.graal.python.nodes.argument.CreateArgumentsNode;
import com.oracle.graal.python.nodes.attributes.ReadAttributeFromObjectNode;
import com.oracle.graal.python.nodes.attributes.WriteAttributeToObjectNode;
import com.oracle.graal.python.nodes.call.CallDispatchNode;
import com.oracle.graal.python.nodes.function.PythonBuiltinBaseNode;
import com.oracle.graal.python.nodes.function.PythonBuiltinNode;
import com.oracle.graal.python.nodes.function.builtins.PythonTernaryBuiltinNode;
import com.oracle.graal.python.nodes.function.builtins.PythonUnaryBuiltinNode;
import com.oracle.graal.python.nodes.subscript.GetItemNode;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.CompilerDirectives.TruffleBoundary;
import com.oracle.truffle.api.dsl.Cached;
import com.oracle.truffle.api.dsl.Fallback;
import com.oracle.truffle.api.dsl.GenerateNodeFactory;
import com.oracle.truffle.api.dsl.NodeFactory;
import com.oracle.truffle.api.dsl.Specialization;
import com.oracle.truffle.api.frame.VirtualFrame;

@CoreFunctions(extendClasses = {PythonBuiltinClassType.PFunction, PythonBuiltinClassType.PBuiltinFunction})
public class AbstractFunctionBuiltins extends PythonBuiltins {

    @Override
    protected List<? extends NodeFactory<? extends PythonBuiltinBaseNode>> getNodeFactories() {
        return AbstractFunctionBuiltinsFactory.getFactories();
    }

    @SuppressWarnings("unused")
    @Builtin(name = __GET__, minNumOfPositionalArgs = 3)
    @GenerateNodeFactory
    public abstract static class GetNode extends PythonTernaryBuiltinNode {
        @Specialization(guards = {"self.isStatic()"})
        protected Object doStatic(PFunction self, Object instance, Object klass) {
            return self;
        }

        @Specialization(guards = {"self.isStatic()"})
        protected Object doBuiltinStatic(PBuiltinFunction self, Object instance, Object klass) {
            return self;
        }

        @Specialization(guards = {"!isNone(instance)", "!self.isStatic()"})
        protected PMethod doMethod(PFunction self, Object instance, Object klass) {
            return factory().createMethod(instance, self);
        }

        @Specialization(guards = {"!isNone(instance)", "!self.isStatic()"})
        protected PBuiltinMethod doBuiltinMethod(PBuiltinFunction self, Object instance, Object klass) {
            return factory().createBuiltinMethod(instance, self);
        }

        @Specialization
        protected Object doFunction(PFunction self, PNone instance, Object klass) {
            return self;
        }

        @Specialization
        protected Object doBuiltinFunction(PBuiltinFunction self, PNone instance, Object klass) {
            return self;
        }
    }

    @Builtin(name = __CALL__, minNumOfPositionalArgs = 1, takesVarArgs = true, takesVarKeywordArgs = true)
    @GenerateNodeFactory
    public abstract static class CallNode extends PythonBuiltinNode {
        @Child private CallDispatchNode dispatch = CallDispatchNode.create();
        @Child private CreateArgumentsNode createArgs = CreateArgumentsNode.create();

        @Specialization
        protected Object doIt(VirtualFrame frame, PFunction self, Object[] arguments, PKeyword[] keywords) {
            return dispatch.executeCall(frame, self, createArgs.execute(self, arguments, keywords));
        }

        @Specialization
        protected Object doIt(VirtualFrame frame, PBuiltinFunction self, Object[] arguments, PKeyword[] keywords) {
            return dispatch.executeCall(frame, self, createArgs.execute(self, arguments, keywords));
        }
    }

    @Builtin(name = __CLOSURE__, minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    public abstract static class GetClosureNode extends PythonBuiltinNode {
        @Specialization(guards = "!isBuiltinFunction(self)")
        Object getClosure(PFunction self) {
            PCell[] closure = self.getClosure();
            if (closure == null) {
                return PNone.NONE;
            }
            return factory().createTuple(closure);
        }

        @SuppressWarnings("unused")
        @Fallback
        Object getClosure(Object self) {
            throw raise(AttributeError, "'builtin_function_or_method' object has no attribute '__closure__'");
        }
    }

    @Builtin(name = __GLOBALS__, minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    public abstract static class GetGlobalsNode extends PythonBuiltinNode {
        @Specialization(guards = "!isBuiltinFunction(self)")
        Object getGlobals(PFunction self) {
            // see the make_globals_function from lib-graalpython/functions.py
            return self.getGlobals();
        }

        @SuppressWarnings("unused")
        @Fallback
        Object getGlobals(Object self) {
            throw raise(AttributeError, "'builtin_function_or_method' object has no attribute '__globals__'");
        }
    }

    @Builtin(name = __MODULE__, minNumOfPositionalArgs = 1, maxNumOfPositionalArgs = 2, isGetter = true, isSetter = true)
    @GenerateNodeFactory
    abstract static class GetModuleNode extends PythonBuiltinNode {
        @Specialization(guards = {"!isBuiltinFunction(self)", "isNoValue(none)"})
        Object getModule(VirtualFrame frame, PFunction self, @SuppressWarnings("unused") PNone none,
                        @Cached("create()") ReadAttributeFromObjectNode readObject,
                        @Cached("create()") GetItemNode getItem,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            Object module = readObject.execute(self, __MODULE__);
            if (module == PNone.NO_VALUE) {
                CompilerDirectives.transferToInterpreter();
                PythonObject globals = self.getGlobals();
                if (globals instanceof PythonModule) {
                    module = globals.getAttribute(__NAME__);
                } else {
                    module = getItem.execute(frame, globals, __NAME__);
                }
                writeObject.execute(self, __MODULE__, module);
            }
            return module;
        }

        @Specialization(guards = {"!isBuiltinFunction(self)", "!isNoValue(value)"})
        Object getModule(PFunction self, Object value,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            writeObject.execute(self, __MODULE__, value);
            return PNone.NONE;
        }

        @SuppressWarnings("unused")
        @Specialization
        Object getModule(PBuiltinFunction self, Object value) {
            throw raise(AttributeError, "'builtin_function_or_method' object has no attribute '__module__'");
        }
    }

    @Builtin(name = __ANNOTATIONS__, minNumOfPositionalArgs = 1, maxNumOfPositionalArgs = 2, isGetter = true, isSetter = true)
    @GenerateNodeFactory
    abstract static class GetAnnotationsNode extends PythonBuiltinNode {
        @Specialization(guards = {"!isBuiltinFunction(self)", "isNoValue(none)"})
        Object getModule(PFunction self, @SuppressWarnings("unused") PNone none,
                        @Cached("create()") ReadAttributeFromObjectNode readObject,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            Object annotations = readObject.execute(self, __ANNOTATIONS__);
            if (annotations == PNone.NO_VALUE) {
                annotations = factory().createDict();
                writeObject.execute(self, __ANNOTATIONS__, annotations);
            }
            return annotations;
        }

        @Specialization(guards = {"!isBuiltinFunction(self)", "!isNoValue(value)"})
        Object getModule(PFunction self, Object value,
                        @Cached("create()") WriteAttributeToObjectNode writeObject) {
            writeObject.execute(self, __ANNOTATIONS__, value);
            return PNone.NONE;
        }

        @SuppressWarnings("unused")
        @Specialization
        Object getModule(PBuiltinFunction self, Object value) {
            throw raise(AttributeError, "'builtin_function_or_method' object has no attribute '__annotations__'");
        }
    }

    @Builtin(name = __DICT__, minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    abstract static class DictNode extends PythonUnaryBuiltinNode {
        @Specialization
        Object dict(PFunction self) {
            PHashingCollection dict = self.getDict();
            if (dict == null) {
                dict = factory().createDictFixedStorage(self);
                self.setDict(dict);
            }
            return dict;
        }

        @SuppressWarnings("unused")
        @Specialization
        Object builtinCode(PBuiltinFunction self) {
            throw raise(AttributeError, "'builtin_function_or_method' object has no attribute '__dict__'");
        }
    }

    @Builtin(name = "__text_signature__", minNumOfPositionalArgs = 1, isGetter = true)
    @GenerateNodeFactory
    public abstract static class TextSignatureNode extends PythonUnaryBuiltinNode {
        @Specialization
        protected Object doStatic(@SuppressWarnings("unused") PBuiltinFunction self) {
            return getSignature(self.getSignature());
        }

        @Specialization
        protected Object doStatic(@SuppressWarnings("unused") PFunction self) {
            return getSignature(self.getSignature());
        }

        @TruffleBoundary
        private static Object getSignature(Signature signature) {
            String[] keywordNames = signature.getKeywordNames();
            boolean takesVarArgs = signature.takesVarArgs();
            boolean takesVarKeywordArgs = signature.takesVarKeywordArgs();

            String[] parameterNames = signature.getParameterIds();
            int paramIdx = 0;

            StringBuilder sb = new StringBuilder();
            char argName = 'a';
            sb.append('(');
            for (int i = 0; i < parameterNames.length; i++) {
                if (paramIdx >= parameterNames.length) {
                    sb.append(", ").append(argName++);
                } else {
                    sb.append(", ").append(parameterNames[paramIdx++]);
                }
            }
            if (parameterNames.length > 0) {
                sb.append(", /");
            }
            if (takesVarArgs) {
                sb.append(", *args");
            }
            if (keywordNames.length > 0) {
                if (!takesVarArgs) {
                    sb.append(", *");
                }
                for (int i = 0; i < keywordNames.length; i++) {
                    sb.append(", ").append(keywordNames[i]).append("=?");
                }
            }
            if (takesVarKeywordArgs) {
                sb.append(", **kwargs");
            }
            sb.append(')');
            return sb.toString();
        }

        public static TextSignatureNode create() {
            return AbstractFunctionBuiltinsFactory.TextSignatureNodeFactory.create();
        }
    }
}
