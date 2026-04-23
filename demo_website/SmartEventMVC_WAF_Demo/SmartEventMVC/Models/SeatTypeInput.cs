namespace SmartEventMVC.Models
{
    public class SeatTypeInput
    {
        public string SeatType { get; set; }   // e.g., "VIP"
        public int Quantity { get; set; }       // number of seats of this type
        public decimal Price { get; set; }      // price per seat
    }
}