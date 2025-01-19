using Grpc.Net.Client;

namespace Accumulator.Utils;

public class GrpcUtils
{
    public static async Task<bool> SendUpdateToNode(int partition, long walletId, long amount, long seqNum)
    {
        var channel = GrpcChannel.ForAddress($"http://localhost:{5000 + partition}");
        var client = new WalletService.WalletServiceClient(channel);

        var response = await client.UpdateWalletAsync(new WalletUpdateRequest
        {
            WalletId = walletId,
            Amount = amount,
            SeqNum = seqNum
        });

        return response.Success;
    }

}