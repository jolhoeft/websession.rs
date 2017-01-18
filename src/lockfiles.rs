use std::io::{Read, Write, BufWriter};

pub struct LockBufWriter<W: Write> {
    bufwriter: BufWriter,
    lockname: String,
}

impl<W: Write> for LockBufWriter<W> {
    fn new(mut lockfile: File, name: &str, inner: W) -> LockBufWriter<W> {
        LockBufWriter {
            bufwriter: BufWriter::new(inner1),
            lockname: name,
        }
        writeln!(lockfile, "{}", unsafe { libc::getpid() });
        // Let lockfile go out of scope so that it closes.
    }

    fn with_capacity(mut lockfile: File, name: &str, cap: usize, inner: W) -> LockBufWriter<W> {
        LockBufWriter {
            bufwriter: BufWriter::with_capacity(cap, inner),
            lockname: name,
        }
        writeln!(lockfile, "{}", unsafe { libc::getpid() });
        // Let lockfile go out of scope so that it closes.
    }

    fn get_ref(&self) -> &W {
        self.bufwriter.get_ref()
    }

    fn get_mut(&mut self) -> &mut W {
        self.bufwriter.get_mut()
    }

    fn into_inner(self) -> Result<W, IntoInnerError<BufWriter<W>>> {
        self.bufwriter.into_inner()
    }
}

impl<W:Write> Write for LockBufWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.bufwriter.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.bufwriter.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.bufwriter.write_all(buf)
    }

    fn write_format(&mut self, fmt: Arguments) -> Result<()> {
        self.bufwriter.write_format(fmt)
    }

    fn by_ref(&mut self) -> &mut Self where Self: Sized {
        self.bufwriter.by_ref()
    }
}

impl<W: Write> fmt::Debug for LockBufWriter<W> where W: fmt::Debug {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.bufwriter.fmt(fmt)
    }
}

impl<W: Write + Seek> Seek for BufWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.bufwriter.seek(pos)
    }
}

impl<W: Write> Drop for LockBufWriter<W> {
    fn drop(&mut self) {
        let _r = fs::remove_file(self.lockname);
    }
}
