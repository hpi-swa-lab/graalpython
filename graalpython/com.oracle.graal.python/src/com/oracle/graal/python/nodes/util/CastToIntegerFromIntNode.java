/*
 * Copyright (c) 2018, Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 *     one is included with the Software (each a "Larger Work" to which the
 *     Software is contributed by such licensors),
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
package com.oracle.graal.python.nodes.util;

import com.oracle.graal.python.builtins.modules.MathGuards;
import com.oracle.graal.python.builtins.objects.PNone;
import com.oracle.graal.python.builtins.objects.ints.PInt;
import com.oracle.graal.python.nodes.PBaseNode;
import com.oracle.graal.python.nodes.PGuards;
import com.oracle.graal.python.nodes.SpecialMethodNames;
import com.oracle.graal.python.nodes.call.special.LookupAndCallUnaryNode;
import com.oracle.graal.python.nodes.truffle.PythonArithmeticTypes;
import static com.oracle.graal.python.runtime.exception.PythonErrorType.TypeError;
import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.dsl.ImportStatic;
import com.oracle.truffle.api.dsl.Specialization;
import com.oracle.truffle.api.dsl.TypeSystemReference;
import com.oracle.truffle.api.nodes.Node;

@TypeSystemReference(PythonArithmeticTypes.class)
@ImportStatic(MathGuards.class)
public abstract class CastToIntegerFromIntNode extends PBaseNode {

    @Node.Child private LookupAndCallUnaryNode callIndexNode;

    public abstract Object execute(Object x);

    public static CastToIntegerFromIntNode create() {
        return CastToIntegerFromIntNodeGen.create();
    }

    @Specialization
    public long toInt(long x) {
        return x;
    }

    @Specialization
    public PInt toInt(PInt x) {
        return x;
    }

    @Specialization
    public long toInt(@SuppressWarnings("unused") double x) {
        throw raise(TypeError, "'%p' object cannot be interpreted as an integer", x);
    }

    @Specialization(guards = "!isNumber(x)")
    public Object toInt(Object x) {
        if (callIndexNode == null) {
            CompilerDirectives.transferToInterpreterAndInvalidate();
            callIndexNode = insert(LookupAndCallUnaryNode.create(SpecialMethodNames.__INT__));
        }
        Object result = callIndexNode.executeObject(x);
        if (result == PNone.NONE) {
            throw raise(TypeError, "'%p' object cannot be interpreted as an integer", x);
        }
        if (!PGuards.isInteger(result) && !PGuards.isPInt(result) && !(result instanceof Boolean)) {
            throw raise(TypeError, " __index__ returned non-int (type %p)", result);
        }
        return result;
    }
}
