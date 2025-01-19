using Accumulator.Wallet;
using FASTER.core;

namespace Accumulator;

public class StoreTest
{
    public static void Main0(string[] args)
    {
        var log = Devices.CreateLogDevice("Logs/hlog-0.log", false);
        var objLog = Devices.CreateLogDevice("Logs/hlog-0.obj.log", false);
        var store = new FasterKV<long, Wallet.Wallet>(
            1L << 20, // Support up to 1 billion wallets
            new LogSettings
            {
                LogDevice = log,
                ObjectLogDevice = objLog,
                MutableFraction = 0.1,
                PageSizeBits = 14,
                MemorySizeBits = 25
            });
        Console.WriteLine("Recovering data from the checkpoint...");
        store.Recover();
        Console.WriteLine("Data recovered successfully.");
        var session = store.NewSession(new WalletFunctions());
        for (long i = 0; i < 100_000; i++)
        {
            Wallet.Wallet output = new Wallet.Wallet();
            session.Read(ref i, ref output);
            Console.WriteLine($"Balance: {output.Balance}, SeqNum: {output.SeqNum}");
        }
        store.Dispose();
        log.Dispose();
        objLog.Dispose();
    }
}