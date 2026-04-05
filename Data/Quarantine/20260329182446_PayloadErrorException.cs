namespace OTPBank.Stage2Azure.Shared.Exceptions
{
    /// <summary>
    /// Payload Exception Class
    /// </summary>
    public class PayloadErrorException : Exception
    {
        public PayloadErrorException(string message) : base(message)
        {

        }

        public PayloadErrorException(string message, Exception innerException) : base(message, innerException)
        {

        }
    }
}
