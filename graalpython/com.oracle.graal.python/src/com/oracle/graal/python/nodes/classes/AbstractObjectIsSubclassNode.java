/*
 * Copyright (c) 2018, 2019, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or
 * data (collectively the "Software"), free of charge and under any and all
 * copyright rights in the Software, and any and all patent rights owned or
 * freely licensable by each licensor hereunder covering either (i) the
 * unmodified Software as contributed to or provided by such licensor, or (ii)
 * the Larger Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at a
 * minimum a reference to the UPL must be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.oracle.graal.python.nodes.classes;

import com.oracle.graal.python.builtins.objects.common.SequenceStorageNodes;
import com.oracle.graal.python.builtins.objects.tuple.PTuple;
import com.oracle.graal.python.nodes.PNodeWithContext;
import com.oracle.graal.python.runtime.PythonOptions;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.dsl.Cached;
import com.oracle.truffle.api.dsl.ImportStatic;
import com.oracle.truffle.api.dsl.Specialization;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.NodeInfo;

@ImportStatic(PythonOptions.class)
@NodeInfo(shortName = "cpython://Objects/abstract.c/abstract_issubclass")
public abstract class AbstractObjectIsSubclassNode extends PNodeWithContext {
    @Child private AbstractObjectGetBasesNode getBasesNode = AbstractObjectGetBasesNode.create();
    @Child private SequenceStorageNodes.LenNode lenNode;

    public static AbstractObjectIsSubclassNode create() {
        return AbstractObjectIsSubclassNodeGen.create();
    }

    public abstract boolean execute(VirtualFrame frame, Object derived, Object cls);

    @Specialization(guards = "derived == cls")
    boolean isSameClass(@SuppressWarnings("unused") Object derived, @SuppressWarnings("unused") Object cls) {
        return true;
    }

    @Specialization(guards = {"derived != cls", "derived == cachedDerived", "cls == cachedCls"}, limit = "getCallSiteInlineCacheMaxDepth()")
    boolean isSubclass(VirtualFrame frame, @SuppressWarnings("unused") Object derived, @SuppressWarnings("unused") Object cls,
                    @Cached("derived") Object cachedDerived,
                    @Cached("cls") Object cachedCls,
                    @Cached("create()") AbstractObjectIsSubclassNode isSubclassNode) {
        // TODO: Investigate adding @ExplodeLoop when the bases is constant in length (guard)
        PTuple bases = getBasesNode.execute(frame, cachedDerived);
        if (bases == null || isEmpty(bases)) {
            return false;
        }

        for (Object baseCls : bases.getArray()) {
            if (isSubclassNode.execute(frame, baseCls, cachedCls)) {
                return true;
            }
        }
        return false;
    }

    @Specialization(replaces = {"isSubclass", "isSameClass"})
    boolean isSubclassGeneric(VirtualFrame frame, Object derived, Object cls,
                    @Cached("create()") AbstractObjectIsSubclassNode isSubclassNode) {
        if (derived == cls) {
            return true;
        }

        PTuple bases = getBasesNode.execute(frame, derived);
        if (bases == null || isEmpty(bases)) {
            return false;
        }

        for (Object baseCls : bases.getArray()) {
            if (isSubclassNode.execute(frame, baseCls, cls)) {
                return true;
            }
        }
        return false;
    }

    private boolean isEmpty(PTuple bases) {
        if (lenNode == null) {
            CompilerDirectives.transferToInterpreterAndInvalidate();
            lenNode = insert(SequenceStorageNodes.LenNode.create());
        }
        return lenNode.execute(bases.getSequenceStorage()) == 0;
    }
}
