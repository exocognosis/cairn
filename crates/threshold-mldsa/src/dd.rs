//! Double-double arithmetic for the mask sampler: a value is `hi + lo` with `|lo|` at most
//! half a unit in the last place of `hi`, about 106 bits in all.
//!
//! Everything here is a fixed sequence of `f64` additions, multiplications, divisions and
//! square roots: no branch on data, no lookup indexed by data, no library call, no fused multiply-add (which is a
//! library call on processors without the instruction). The inputs decide secret masks.
//! `scripts/ct-check.sh` checks the compiled `ln` and `cos_sin_turn` for branches and calls;
//! the `sampler_precision` tests check every function against 256-bit arithmetic.

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Dd(pub f64, pub f64);

#[inline(always)]
fn two_sum(a: f64, b: f64) -> Dd {
    let s = a + b;
    let bb = s - a;
    Dd(s, (a - (s - bb)) + (b - bb))
}

/// Requires `|a| >= |b|`.
#[inline(always)]
fn quick_two_sum(a: f64, b: f64) -> Dd {
    let s = a + b;
    Dd(s, b - (s - a))
}

#[inline(always)]
fn split(a: f64) -> (f64, f64) {
    let t = 134_217_729.0 * a;
    let hi = t - (t - a);
    (hi, a - hi)
}

/// Exact product of two doubles (Dekker), without a fused multiply-add.
#[inline(always)]
fn two_prod(a: f64, b: f64) -> Dd {
    let p = a * b;
    let ((ah, al), (bh, bl)) = (split(a), split(b));
    Dd(p, ((ah * bh - p) + ah * bl + al * bh) + al * bl)
}

impl Dd {
    pub const ZERO: Dd = Dd(0.0, 0.0);
    pub const ONE: Dd = Dd(1.0, 0.0);
    const LN_2: Dd = Dd(std::f64::consts::LN_2, 2.319_046_813_846_299_6e-17);
    const TWO_PI: Dd = Dd(std::f64::consts::TAU, 2.449_293_598_294_706_4e-16);
    /// `1/(2k+1)` for the `atanh` series, to double-double precision.
    #[rustfmt::skip]
    const ODD_RECIPROCALS: [Dd; 22] = [
        Dd(1.0, 0.0),
        Dd(0.3333333333333333, 1.850371707708594e-17),
        Dd(0.2, -1.1102230246251566e-17),
        Dd(0.14285714285714285, 7.93016446160826e-18),
        Dd(0.1111111111111111, 6.1679056923619804e-18),
        Dd(0.09090909090909091, -2.523234146875356e-18),
        Dd(0.07692307692307693, -4.270088556250602e-18),
        Dd(0.06666666666666667, 9.251858538542971e-19),
        Dd(0.058823529411764705, 8.163404592832033e-19),
        Dd(0.05263157894736842, 2.921639538487254e-18),
        Dd(0.047619047619047616, 2.64338815386942e-18),
        Dd(0.043478260869565216, 1.206764157201257e-18),
        Dd(0.04, -8.326672684688674e-19),
        Dd(0.037037037037037035, 2.05596856412066e-18),
        Dd(0.034482758620689655, 4.785444071660157e-19),
        Dd(0.03225806451612903, 8.953411488912552e-19),
        Dd(0.030303030303030304, -8.410780489584519e-19),
        Dd(0.02857142857142857, 8.921435019309293e-19),
        Dd(0.02702702702702703, -1.50030138462859e-18),
        Dd(0.02564102564102564, 8.896017825522087e-19),
        Dd(0.024390243902439025, -8.46206573647223e-19),
        Dd(0.023255813953488372, 3.2273925134452225e-19),
    ];
    /// `1/((2j+1)(2j+2))`: the ratio of consecutive cosine Taylor terms.
    #[rustfmt::skip]
    const COS_STEPS: [Dd; 16] = [
        Dd(0.5, 0.0),
        Dd(0.08333333333333333, 4.625929269271485e-18),
        Dd(0.03333333333333333, 4.625929269271486e-19),
        Dd(0.017857142857142856, 9.912705577010326e-19),
        Dd(0.011111111111111112, -4.2404351634988616e-19),
        Dd(0.007575757575757576, -2.1026951223961299e-19),
        Dd(0.005494505494505495, -4.2891514515910067e-19),
        Dd(0.004166666666666667, 5.782411586589357e-20),
        Dd(0.0032679738562091504, -9.920804192677818e-20),
        Dd(0.002631578947368421, 5.934580312552235e-20),
        Dd(0.0021645021645021645, 1.8774063592822588e-21),
        Dd(0.0018115942028985507, -2.199830494898125e-20),
        Dd(0.0015384615384615385, 1.3344026738283131e-21),
        Dd(0.0013227513227513227, 7.3427448718595e-20),
        Dd(0.0011494252873563218, 1.595148023886719e-20),
        Dd(0.0010080645161290322, 2.7979410902851727e-20),
    ];
    /// `1/((2j+2)(2j+3))`: the same for sine.
    #[rustfmt::skip]
    const SIN_STEPS: [Dd; 16] = [
        Dd(0.16666666666666666, 9.25185853854297e-18),
        Dd(0.05, -2.7755575615628915e-18),
        Dd(0.023809523809523808, 1.32169407693471e-18),
        Dd(0.013888888888888888, 7.709882115452476e-19),
        Dd(0.00909090909090909, 4.415659757031872e-19),
        Dd(0.00641025641025641, 2.2240044563805217e-19),
        Dd(0.004761904761904762, -4.295505750037808e-19),
        Dd(0.003676470588235294, 5.102127870520021e-20),
        Dd(0.0029239766081871343, 1.6231330769373633e-19),
        Dd(0.002380952380952381, -2.147752875018904e-19),
        Dd(0.001976284584980237, 1.3370398332627564e-19),
        Dd(0.0016666666666666668, -1.0697461435190311e-19),
        Dd(0.0014245014245014246, -7.104458680104445e-20),
        Dd(0.0012315270935960591, -1.3886333243656708e-20),
        Dd(0.001075268817204301, 9.326470300950576e-22),
        Dd(0.000946969696969697, -2.6283689029951623e-20),
    ];

    /// `hi + lo` for any two doubles.
    #[inline(always)]
    pub fn from_sum(hi: f64, lo: f64) -> Dd {
        two_sum(hi, lo)
    }

    #[inline(always)]
    pub fn add(self, o: Dd) -> Dd {
        let s = two_sum(self.0, o.0);
        let t = two_sum(self.1, o.1);
        let v = quick_two_sum(s.0, s.1 + t.0);
        quick_two_sum(v.0, t.1 + v.1)
    }

    #[inline(always)]
    pub fn neg(self) -> Dd {
        Dd(-self.0, -self.1)
    }

    #[inline(always)]
    pub fn sub(self, o: Dd) -> Dd {
        self.add(o.neg())
    }

    #[inline(always)]
    pub fn mul(self, o: Dd) -> Dd {
        let p = two_prod(self.0, o.0);
        quick_two_sum(p.0, p.1 + (self.0 * o.1 + self.1 * o.0))
    }

    #[inline(always)]
    pub fn mul_f64(self, b: f64) -> Dd {
        let p = two_prod(self.0, b);
        quick_two_sum(p.0, p.1 + self.1 * b)
    }

    #[inline(always)]
    pub fn div(self, o: Dd) -> Dd {
        let q1 = self.0 / o.0;
        let r = self.sub(o.mul_f64(q1));
        let q2 = r.0 / o.0;
        let r = r.sub(o.mul_f64(q2));
        let q3 = r.0 / o.0;
        quick_two_sum(q1, q2).add(Dd(q3, 0.0))
    }

    /// Square root of a positive value.
    #[inline(always)]
    pub fn sqrt(self) -> Dd {
        let s = self.0.sqrt();
        let p = two_prod(s, s);
        let e = ((self.0 - p.0) - p.1 + self.1) / (2.0 * s);
        quick_two_sum(s, e)
    }

    /// Nearest integer, for `|self| < 2^51`. An exact half-integer may go either way.
    #[inline(always)]
    pub fn round(self) -> i64 {
        // Adding and subtracting 1.5 * 2^52 rounds a double to an integer with plain adds.
        const MAGIC: f64 = 6_755_399_441_055_744.0;
        let n = (self.0 + MAGIC) - MAGIC;
        // hi - n is exact and at most 1/2 in size; lo, at most half a unit in the last place
        // of hi, can only change the answer when hi sits exactly on a half-integer.
        let d = self.0 - n;
        n as i64 + ((d == 0.5) & (self.1 > 0.0)) as i64 - ((d == -0.5) & (self.1 < 0.0)) as i64
    }

    /// Natural logarithm for `self` in `(0, 1)`.
    #[inline(never)]
    pub fn ln(self) -> Dd {
        let bits = self.0.to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as i64 - 1023;
        // Scale by an exact power of two so that hi is in [1, 2), then into
        // [sqrt(1/2), sqrt(2)) by halving the upper part.
        let scale = f64::from_bits(((1023 - exponent) as u64) << 52);
        let upper = (self.0 * scale >= std::f64::consts::SQRT_2) as i64;
        let scale = scale * (1.0 - 0.5 * upper as f64);
        let m = Dd(self.0 * scale, self.1 * scale);
        let e = (exponent + upper) as f64;
        // ln m = 2 atanh(s), s = (m - 1)/(m + 1), s^2 < 0.0295: 22 terms reach 1e-34.
        let s = m.sub(Dd::ONE).div(m.add(Dd::ONE));
        let s2 = s.mul(s);
        let mut p = Dd::ZERO;
        for k in (0..22).rev() {
            p = p.mul(s2).add(Dd::ODD_RECIPROCALS[k]);
        }
        Dd::LN_2.mul_f64(e).add(s.mul(p).mul_f64(2.0))
    }

    /// `(cos(2 pi u), sin(2 pi u))` for `u` in `[0, 1)`. The quadrant is applied by arithmetic.
    #[inline(never)]
    pub fn cos_sin_turn(self) -> (Dd, Dd) {
        // u = k/4 + r with |r| <= 1/8 (to within lo); hi - k/4 is exact.
        let k = (4.0 * self.0 + 0.5) as i64;
        let r = two_sum(self.0 - k as f64 * 0.25, self.1);
        let theta = Dd::TWO_PI.mul(r);
        let t2 = theta.mul(theta);
        // Taylor series on |theta| <= pi/4 in Horner form, truncation below 1e-38.
        let (mut cos, mut sin) = (Dd::ZERO, Dd::ZERO);
        for j in (0..=15).rev() {
            cos = Dd::ONE.sub(t2.mul(Dd::COS_STEPS[j]).mul(cos));
            sin = Dd::ONE.sub(t2.mul(Dd::SIN_STEPS[j]).mul(sin));
        }
        let sin = theta.mul(sin);
        // cos(theta + k pi/2): k = 0, 1, 2, 3 gives cos, -sin, -cos, sin.
        let (odd, half) = (k & 1, k & 2);
        let from_cos = ((1 - odd) * (1 - half)) as f64;
        let from_sin = (odd * (half - 1)) as f64;
        // sin(theta + k pi/2): sin, cos, -sin, -cos.
        (
            cos.mul_f64(from_cos).add(sin.mul_f64(from_sin)),
            sin.mul_f64(from_cos).sub(cos.mul_f64(from_sin)),
        )
    }
}
