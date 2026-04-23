namespace SmartEventMVC.Models
{
    public class HomeEventViewModel
    {
        public Event Event { get; set; }
        public decimal MinPrice { get; set; }
        public decimal MaxPrice { get; set; }
        public int AvailableSeats { get; set; }
        public double AverageRating { get; set; }
        public int ReviewCount { get; set; }

        // Display helper
        public string PriceDisplay => MinPrice == MaxPrice
            ? $"LKR {MinPrice:N2}"
            : $"LKR {MinPrice:N2} – {MaxPrice:N2}";
    }
}