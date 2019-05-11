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
package com.oracle.graal.python.nodes;

import com.oracle.graal.python.builtins.objects.function.Signature;
import com.oracle.truffle.api.Assumption;
import com.oracle.truffle.api.CompilerAsserts;
import com.oracle.truffle.api.CompilerDirectives.CompilationFinal;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleLanguage;
import com.oracle.truffle.api.frame.FrameDescriptor;
import com.oracle.truffle.api.nodes.RootNode;

public abstract class PRootNode extends RootNode {
    @CompilationFinal private Assumption dontNeedCallerFrame = Truffle.getRuntime().createAssumption("does not need caller frame");

    /**
     * Flag indicating if some child node of this root node eventually needs the exception state.
     * Hence, the caller of this root node should provide the exception state in the arguments.
     */
    @CompilationFinal private Assumption dontNeedExceptionState = Truffle.getRuntime().createAssumption("does not need exception state");

    protected PRootNode(TruffleLanguage<?> language) {
        super(language);
    }

    protected PRootNode(TruffleLanguage<?> language, FrameDescriptor frameDescriptor) {
        super(language, frameDescriptor);
    }

    public boolean needsCallerFrame() {
        return !dontNeedCallerFrame.isValid();
    }

    public void setNeedsCallerFrame() {
        CompilerAsserts.neverPartOfCompilation("this is usually called from behind a TruffleBoundary");
        dontNeedCallerFrame.invalidate();
    }

    public boolean needsExceptionState() {
        return !dontNeedExceptionState.isValid();
    }

    public void setNeedsExceptionState() {
        CompilerAsserts.neverPartOfCompilation("this is usually called from behind a TruffleBoundary");
        dontNeedExceptionState.invalidate();
    }

    @Override
    public boolean isCaptureFramesForTrace() {
        return true;
    }

    @Override
    public boolean isCloningAllowed() {
        return true;
    }

    public abstract Signature getSignature();

    protected void setDontNeedCallerFrame(Assumption dontNeedCallerFrame) {
        this.dontNeedCallerFrame = dontNeedCallerFrame;
    }

    protected void setDontNeedExceptionState(Assumption dontNeedExceptionState) {
        this.dontNeedExceptionState = dontNeedExceptionState;
    }

    protected Assumption getDontNeedCallerFrame() {
        return dontNeedCallerFrame;
    }

    protected Assumption getDontNeedExceptionState() {
        return dontNeedExceptionState;
    }
}
