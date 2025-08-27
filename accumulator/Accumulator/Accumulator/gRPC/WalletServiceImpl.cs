// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

using Accumulator.Wallet;
using FASTER.core;
using Grpc.Core;

namespace Accumulator.gRPC;

public class WalletServiceImpl : WalletService.WalletServiceBase
{
    private readonly FasterKV<long, Wallet.Wallet> _store;

    public WalletServiceImpl(FasterKV<long, Wallet.Wallet> store)
    {
        _store = store;
    }
    
    public override Task<ReadyResponse> Ready(ReadyRequest request, ServerCallContext context)
    {
        return Task.FromResult(new ReadyResponse { Ready = true });
    }

    public override Task<WalletBatchUpdateResponse> UpdateWallets(WalletBatchUpdateRequest request, ServerCallContext context)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        using var session = _store.NewSession(new WalletFunctions());
        var isUndo = request.IsUndo;
        if (isUndo)
        {
            foreach (var update in request.Updates)
            {
                if (session.Read(update.WalletId, out var wallet).Found)
                {
                    wallet.Balance -= update.Amount;
                    session.Upsert(update.WalletId, wallet);
                }
            }
        }
        else
        {
            foreach (var update in request.Updates)
            {
                if (session.Read(update.WalletId, out var wallet).Found)
                {
                    wallet.Balance += update.Amount;
                    session.Upsert(update.WalletId, wallet);
                }
            }
        }
        stopwatch.Stop();
        Console.WriteLine($"Processed {request.Updates.Count} updates in {stopwatch.ElapsedMilliseconds}ms.");

        return Task.FromResult(new WalletBatchUpdateResponse { Success = true });
    }
}

