// A REAL std Rust program: heap allocation (Vec), iterators, string
// formatting, and buffered stdout via println! (→ write syscall). Static musl.
fn main() {
    let squares: Vec<u64> = (1..=10).map(|n| n * n).collect();
    let sum: u64 = squares.iter().sum();
    println!("rust ecosystem native: squares={:?}", squares);
    println!("sum={sum}");
    std::process::exit((sum % 256) as i32);
}
