/*
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _ATOMIC_H
#define _ATOMIC_H

/*
 * Atomic operations only work on:
 *	GCC >= 4.1
 *	Clang / LLVM
 */

/**
 * Atomic type and operations equivalent to the Linux kernel.
 */
typedef struct {
	volatile int counter;
} atomic_t;

/**
 * Memory barrier
 */
static inline void mb(void)
{
	__sync_synchronize();
}

#define ATOMIC_INIT(i)  { (i) }

/**
 * Read atomic variable
 * @param v atomic variable
 * @return variable content
 */
static inline int atomic_read(const atomic_t *v)
{
	int i;

	mb();	
	i = ((v)->counter);
	mb();

	return i;
}

/**
 * Set atomic variable
 * @param i value to be set
 * @param v atomic variable
 */
static inline void atomic_set(int i, atomic_t *v)
{
	mb();
	((v)->counter) = i;
	mb();
}

/**
 * Atomic add operation
 * @param i integer value to add
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_add(int i, atomic_t *v)
{
	return __sync_add_and_fetch(&v->counter, i);
}

/**
 * Atomic add value from variable and test for zero
 * @param i integer value to add
 * @param v atomic variable
 * @return true if the result is zero, or false for all other cases.
 */
static inline int atomic_add_and_test(int i, atomic_t *v)
{
	return !(__sync_add_and_fetch(&v->counter, i));
}

/**
 * Atomic increment by 1
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_inc(atomic_t *v)
{
	return atomic_add(1, v);
}

/**
 * Atomic increment and test for zero
 * @param v pointer of type atomic_t
 * @return true if the result is zero, or false for all other cases.
 */
static inline int atomic_inc_and_test(atomic_t *v)
{
	return atomic_add_and_test(1, v);
}

/**
 * Atomic subtract operation
 * @param i integer value to subtract
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_sub(int i, atomic_t *v)
{
	return __sync_sub_and_fetch(&v->counter, i);
}

/**
 * Atomic subtract value from variable and test for zero
 * @param i integer value to subtract
 * @param v atomic variable
 * @return true if the result is zero, or false for all other cases.
 */
static inline int atomic_sub_and_test(int i, atomic_t *v)
{
	return !(__sync_sub_and_fetch(&v->counter, i));
}

/**
 * Atomic decrement by 1
 * @param v: atomic variable
 * @return variable content after operation
 */
static inline int atomic_dec(atomic_t *v)
{
	return atomic_sub(1, v);
}

/**
 * Atomic decrement by 1 and test for zero
 * @param v atomic variable
 * @return true if the result is zero, or false for all other cases.
 */
static inline int atomic_dec_and_test(atomic_t *v)
{
	return atomic_sub_and_test(1, v);
}

/**
 * Atomic or operation
 * @param i integer value to or
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_or(int i, atomic_t *v)
{
	return __sync_or_and_fetch(&v->counter, i);
}

/**
 * Atomic xor operation
 * @param i integer value to xor
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_xor(int i, atomic_t *v)
{
	return __sync_xor_and_fetch(&v->counter, i);
}

/**
 * Atomic and operation
 * @param i integer value to and
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_and(int i, atomic_t *v)
{
	return __sync_and_and_fetch(&v->counter, i);
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsync-fetch-and-nand-semantics-changed"
#endif
/**
 * Atomic nand operation
 * @param i integer value to nand
 * @param v atomic variable
 * @return variable content after operation
 */
static inline int atomic_nand(int i, atomic_t *v)
{
	return __sync_nand_and_fetch(&v->counter, i);
}
#ifdef __clang__
#pragma clang diagnostic pop
#endif

/**
 * Atomic compare and exchange operation (if current value of atomic
 * variable is equal to the old value, set the new value)
 * @param v atomic variable
 * @param old integer value to compare with
 * @param new integer value to set atomic variable to
 * @return true if comparison is successful and new was written
 */
static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return __sync_bool_compare_and_swap(&v->counter, old, new);
}

#endif
